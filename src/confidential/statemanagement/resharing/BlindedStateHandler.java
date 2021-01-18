package confidential.statemanagement.resharing;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.Configuration;
import confidential.polynomial.PolynomialCreationContext;
import confidential.server.Request;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.ReconstructionCompleted;
import confidential.statemanagement.utils.PublicDataReceiver;
import confidential.statemanagement.utils.PublicStateListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BlindedStateHandler extends Thread implements PublicStateListener {
    protected final Logger logger = LoggerFactory.getLogger("confidential");

    protected final int oldThreshold;
    protected final int newThreshold;
    protected final int oldQuorum;
    private final AtomicInteger corruptedServers;
    protected final Set<Integer> stillValidSenders;

    protected final int processId;
    protected final ServerConfidentialityScheme confidentialityScheme;
    protected final BigInteger field;
    protected final CommitmentScheme commitmentScheme;
    protected final InterpolationStrategy interpolationStrategy;
    protected final int stateSenderReplica;
    protected final BigInteger shareholderId;

    private final Map<Integer, Integer> commonState;
    private byte[] selectedCommonState;
    private int selectedCommonStateHash;
    private ObjectInput commonStateStream;
    private int nCommonStateReceived;

    private final Map<Integer, LinkedList<Share>> blindedShares;
    private final Map<Integer, Integer> blindedSharesSize;
    private int correctBlindedSharesSize;

    private final Lock lock = new ReentrantLock();
    private final Condition condition = lock.newCondition();

    private PublicDataReceiver publicDataReceiver;
    private final ReconstructionCompleted reconstructionListener;

    public BlindedStateHandler(ServerViewController svController,
                               PolynomialCreationContext context,
                               ServerConfidentialityScheme confidentialityScheme,
                               int stateSenderReplica,
                               int serverPort,
                               ReconstructionCompleted reconstructionListener) {
        super("Blinded State Handler Thread");
        this.reconstructionListener = reconstructionListener;
        this.oldThreshold = context.getContexts()[0].getF();
        this.newThreshold = context.getContexts()[1].getF();
        this.oldQuorum = context.getContexts()[0].getMembers().length - oldThreshold;
        this.processId = svController.getStaticConf().getProcessId();
        this.confidentialityScheme = confidentialityScheme;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.interpolationStrategy = confidentialityScheme.getInterpolationStrategy();
        this.field = confidentialityScheme.getField();
        this.stateSenderReplica = stateSenderReplica;
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.stillValidSenders = new HashSet<>(oldQuorum);
        this.commonState = new HashMap<>(oldQuorum);
        this.blindedShares = new HashMap<>(oldQuorum);
        this.blindedSharesSize = new HashMap<>(oldQuorum);
        this.corruptedServers = new AtomicInteger(0);

        this.correctBlindedSharesSize = -1;
        int[] receiversId = context.getContexts()[0].getMembers();
        try {
            int port = serverPort + processId;
            this.publicDataReceiver = new PublicDataReceiver(this, svController, port,
                    stateSenderReplica, receiversId);
            this.publicDataReceiver.start();
        } catch (IOException e) {
            logger.error("Failed to initialize public data receiver thread", e);
        }
    }

    @Override
    public void deliverPublicState(int from, byte[] serializedBlindedShares,
                                   byte[] serializedCommitments, byte[] commitmentsHash,
                                   byte[] serializedCommonState, byte[] commonStateHash) {
        lock.lock();
        if (commonStateStream == null) {
            int commonStateHashCode = Arrays.hashCode(commonStateHash);
            if (from == stateSenderReplica) {
                selectedCommonState = serializedCommonState;
                selectedCommonStateHash = commonStateHashCode;
                logger.debug("Replica {} sent me a common state of {} bytes", from, serializedCommonState.length);
            } else {
                logger.debug("Replica {} sent me hash of a common state", from);
            }

            commonState.merge(commonStateHashCode, 1, Integer::sum);

            handleNewCommitments(from, serializedCommitments, commitmentsHash);

            nCommonStateReceived++;
        }

        LinkedList<Share> blindedShares = deserializeBlindedShares(from, serializedBlindedShares);
        if (blindedShares != null) {
            this.blindedShares.put(from, blindedShares);
            this.blindedSharesSize.merge(blindedShares.size(), 1, Integer::sum);
            stillValidSenders.add(from);
        }

        condition.signalAll();
        lock.unlock();
    }

    protected abstract void handleNewCommitments(int from, byte[] serializedCommitments, byte[] commitmentsHash);
    protected abstract boolean prepareCommitments();
    protected abstract Map<BigInteger, Commitment> readNextCommitment() throws IOException, ClassNotFoundException;

    @Override
    public void run() {
        while (true) {
            try {
                lock.lock();
                condition.await();
                if (blindedShares.size() < oldQuorum || selectedCommonState == null
                        || nCommonStateReceived < oldQuorum/* || (commitmentsStreams != null && commitmentsStreams.size() < oldQuorum)*/)
                    continue;
                logger.debug("I have received enough states");
                if (commonStateStream == null) {
                    if (haveCorrectState(selectedCommonState, commonState, selectedCommonStateHash))
                        commonStateStream = new ObjectInputStream(new ByteArrayInputStream(selectedCommonState));
                    else
                        logger.debug("I don't have enough same states");
                }
                if (!prepareCommitments()) {
                    continue;
                }
                if (correctBlindedSharesSize == -1) {
                    correctBlindedSharesSize = selectCorrectKey(blindedSharesSize);
                    logger.debug("I have received {} secret blinded shares", correctBlindedSharesSize);
                }
                if (commonStateStream != null && correctBlindedSharesSize != -1) {
                    logger.info("Reconstructing state");
                    long startTime = System.nanoTime();
                    DefaultApplicationState refreshedState = refreshState();
                    if (refreshedState == null) {
                        logger.error("Refreshed state is null. Waiting for more blinded states.");
                        continue;
                    }
                    long endTime = System.nanoTime();
                    double totalTime = (endTime - startTime) / 1_000_000.0;
                    logger.info("State Refresh duration: {} ms", totalTime);
                    reconstructionListener.onReconstructionCompleted(refreshedState);
                    break;

                } else {
                    logger.debug("Common state stream is null? {} | correct blinded shares size: {}",
                            commonStateStream == null, correctBlindedSharesSize);
                }
            } catch (InterruptedException e) {
                logger.error("Failed to poll state from queue", e);
            } catch (IOException e) {
                logger.debug("Failed to load common state");
            } finally {
                lock.unlock();
            }
        }

        publicDataReceiver.interrupt();
        logger.debug("Exiting blinded state handler thread");
    }

    private DefaultApplicationState refreshState() {
        try {
            int nShares = -1;

            //Collecting all blinded shares
            Map<Integer, Share[]> allBlindedShares = new HashMap<>(stillValidSenders.size());
            Share[] shareTemp;
            for (Map.Entry<Integer, LinkedList<Share>> entry : blindedShares.entrySet()) {
                int i = 0;
                if (nShares == -1) {
                    nShares = entry.getValue().size();
                }
                shareTemp = new Share[nShares];
                for (Share share : entry.getValue()) {
                    shareTemp[i++] = share;
                }
                allBlindedShares.put(entry.getKey(), shareTemp);
            }

            //Collecting all commitments
            Map<BigInteger, Commitment[]> allBlindedCommitments = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment[]> allRCommitments = new HashMap<>(stillValidSenders.size());
            Commitment[] commitmentTemp;
            Map<BigInteger, Commitment> commitments;
            Map<BigInteger, Commitment> rCommitments;
            for (int i = 0; i < nShares; i++) {
                commitments = readNextCommitment();
                rCommitments = readNextCommitment();
                for (Map.Entry<BigInteger, Commitment> commitment : commitments.entrySet()) {
                    commitmentTemp = allBlindedCommitments.get(commitment.getKey());
                    if (commitmentTemp == null) {
                        commitmentTemp = new Commitment[nShares];
                        allBlindedCommitments.put(commitment.getKey(), commitmentTemp);
                    }
                    commitmentTemp[i] = commitment.getValue();
                }
                for (Map.Entry<BigInteger, Commitment> commitment : rCommitments.entrySet()) {
                    commitmentTemp = allRCommitments.get(commitment.getKey());
                    if (commitmentTemp == null) {
                        commitmentTemp = new Commitment[nShares];
                        allRCommitments.put(commitment.getKey(), commitmentTemp);
                    }
                    commitmentTemp[i] = commitment.getValue();
                }
            }

            long t1, t2;
            t1 = System.nanoTime();
            Iterator<VerifiableShare> refreshedShares = refreshShares(nShares, allBlindedShares,
                    allBlindedCommitments, allRCommitments);
            t2 = System.nanoTime();
            if (refreshedShares == null) {
                logger.error("Failed to refresh shares");
                return null;
            }
            double duration = (t2 - t1) / 1_000_000.0;
            logger.info("Took {} ms to refresh {} shares", duration, nShares);

            int lastCheckPointCID = commonStateStream.readInt();
            int lastCID = commonStateStream.readInt();
            int logSize = commonStateStream.readInt();

            CommandsInfo[] refreshedLog = null;
            if (logSize > -1) {
                refreshedLog = refreshLog(logSize, refreshedShares);
                if (refreshedLog == null) {
                    logger.error("Failed to refresh log");
                    return null;
                }
            }

            //refresh snapshot
            boolean hasState = commonStateStream.readBoolean();
            ConfidentialSnapshot refreshedSnapshot = null;

            if (hasState) {
                refreshedSnapshot = refreshSnapshot(refreshedShares);
            }

            byte[] refreshedSerializedState = refreshedSnapshot == null ? null : refreshedSnapshot.serialize();
            return new DefaultApplicationState(
                    refreshedLog,
                    lastCheckPointCID,
                    lastCID,
                    refreshedSerializedState,
                    refreshedSerializedState == null ? null : TOMUtil.computeHash(refreshedSerializedState),
                    processId
            );
        } catch (IOException | ClassNotFoundException | SecretSharingException | InterruptedException e) {
            logger.error("Failed to reconstruct refreshed state", e);
            return null;
        }
    }

    private Iterator<VerifiableShare> refreshShares(int nShares, Map<Integer, Share[]> allBlindedShares,
                                                    Map<BigInteger, Commitment[]> allBlindedCommitments,
                                                    Map<BigInteger, Commitment[]> allRCommitments)
            throws InterruptedException {
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        VerifiableShare[] refreshedShares = new VerifiableShare[nShares];
        CountDownLatch shareProcessingCounter = new CountDownLatch(nShares);
        Integer[] servers = new Integer[allBlindedShares.size()];
        BigInteger[] shareholders = new BigInteger[allBlindedCommitments.size()];
        int k = 0;
        //Load share senders
        for (Integer server : allBlindedShares.keySet()) {
            servers[k++] = server;
        }
        k = 0;
        //Load commitments senders
        for (BigInteger shareholder : allBlindedCommitments.keySet()) {
            shareholders[k++] = shareholder;
        }

        for (int i = 0; i < nShares; i++) {
            int finalI = i;
            Map<Integer, Share> blindedShares = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment> blindedCommitments = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment> rCommitments = new HashMap<>(stillValidSenders.size());
            for (Integer server : servers) {
                blindedShares.put(server, allBlindedShares.get(server)[i]);
            }
            for (BigInteger shareholder : shareholders) {
                blindedCommitments.put(shareholder, allBlindedCommitments.get(shareholder)[i]);
                rCommitments.put(shareholder, allRCommitments.get(shareholder)[i]);
            }
            executorService.execute(() -> {
                try {
                    VerifiableShare vs = recoverShare(blindedShares, blindedCommitments, rCommitments);
                    if (vs == null) {
                        return;
                    }
                    refreshedShares[finalI] = vs;
                    shareProcessingCounter.countDown();
                } catch (IOException | ClassNotFoundException e) {
                    logger.error("Failed to refresh share.", e);
                }
            });
        }
        shareProcessingCounter.await();
        executorService.shutdown();
        LinkedList<VerifiableShare> result = new LinkedList<>();
        for (VerifiableShare refreshedShare : refreshedShares) {
            if (refreshedShare == null)
                return null;
            result.add(refreshedShare);
        }
        return result.iterator();
    }

    private CommandsInfo[] refreshLog(int logSize, Iterator<VerifiableShare> refreshedShares) throws IOException,
            ClassNotFoundException, SecretSharingException {
        logger.info("Refreshing log");
        CommandsInfo[] log = new CommandsInfo[logSize];
        for (int i = 0; i < logSize; i++) {
            MessageContext[] msgCtx = deserializeMessageContext(commonStateStream);
            int nCommands = commonStateStream.readInt();
            byte[][] commands = new byte[nCommands][];
            for (int j = 0; j < nCommands; j++) {
                int nShares = commonStateStream.readInt();
                byte[] command;
                if (nShares == -1) {
                    command = new byte[commonStateStream.readInt()];
                    commonStateStream.readFully(command);
                } else {
                    ConfidentialData[] shares = getRefreshedShares(nShares, refreshedShares);

                    byte[] b = new byte[commonStateStream.readInt()];
                    commonStateStream.readFully(b);
                    Request request = Request.deserialize(b);
                    if (request == null) {
                        logger.error("Failed to deserialize request");
                        return null;
                    }
                    request.setShares(shares);
                    command = request.serialize();
                    if (command == null) {
                        logger.error("Failed to serialize request");
                        return null;
                    }
                }
                commands[j] = command;
            }
            log[i] = new CommandsInfo(commands, msgCtx);
        }
        return log;
    }

    private ConfidentialSnapshot refreshSnapshot(Iterator<VerifiableShare> refreshedShares)
            throws IOException, ClassNotFoundException, SecretSharingException {
        logger.info("Refreshing snapshot");
        int plainDataSize = commonStateStream.readInt();
        byte[] plainData = null;
        if (plainDataSize > -1) {
            plainData = new byte[plainDataSize];
            commonStateStream.readFully(plainData);
        }

        int nShares = commonStateStream.readInt();
        ConfidentialData[] snapshotShares = null;

        if (nShares > -1) {
            snapshotShares = getRefreshedShares(nShares, refreshedShares);
        }

        return snapshotShares == null ?
                new ConfidentialSnapshot(plainData)
                : new ConfidentialSnapshot(plainData, snapshotShares);
    }

    private ConfidentialData[] getRefreshedShares(int nShares, Iterator<VerifiableShare> refreshedShares)
            throws IOException {
        ConfidentialData[] shares = new ConfidentialData[nShares];
        for (int i = 0; i < nShares; i++) {
            int shareDataSize = commonStateStream.readInt();
            byte[] sharedData = null;
            if (shareDataSize > -1) {
                sharedData = new byte[shareDataSize];
                commonStateStream.readFully(sharedData);
            }
            VerifiableShare vs = refreshedShares.next();
            refreshedShares.remove();
            vs.setSharedData(sharedData);
            shares[i] = new ConfidentialData(vs);
        }
        return shares;
    }

    private VerifiableShare recoverShare(Map<Integer, Share> allBlindedShares,
                                         Map<BigInteger, Commitment> allBlindedCommitments,
                                         Map<BigInteger, Commitment> rCommitments) throws IOException, ClassNotFoundException {
        try {
            int corruptedServers = this.corruptedServers.get();
            Share[] blindedShares = new Share[oldThreshold + (corruptedServers < oldThreshold ? 2 : 1)];
            Commitment combinedBlindedCommitments = commitmentScheme.combineCommitments(allBlindedCommitments);
            Commitment combinedRCommitments = commitmentScheme.combineCommitments(rCommitments);
            Commitment verificationCommitment = commitmentScheme.sumCommitments(combinedBlindedCommitments,
                    combinedRCommitments);

            Map<BigInteger, Commitment> validCommitments = new HashMap<>(oldThreshold + 1);
            Set<Integer> invalidServers = new HashSet<>(oldThreshold);
            int j = 0;
            for (Map.Entry<Integer, Share> entry : allBlindedShares.entrySet()) {
                Share share = entry.getValue();
                int server = entry.getKey();
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                if (commitmentScheme.checkValidityWithoutPreComputation(share, verificationCommitment)) {
                    blindedShares[j] = share;
                    if (validCommitments.size() <= oldThreshold) {
                        validCommitments.put(shareholder, allBlindedCommitments.get(shareholder));
                    }
                } else {
                    logger.error("Server {} sent me an invalid share", server);
                    allBlindedCommitments.remove(shareholder);
                    rCommitments.remove(shareholder);
                    this.corruptedServers.incrementAndGet();
                    invalidServers.add(server);
                    stillValidSenders.remove(server);
                }
                j++;
                if (j == blindedShares.length) {
                    break;
                }
            }

            for (Integer server : invalidServers) {
                allBlindedShares.remove(server);
            }

            BigInteger recoveredShare = interpolationStrategy.interpolateAt(shareholderId, blindedShares);
            Commitment commitment = commitmentScheme.recoverCommitment(shareholderId, validCommitments);

            Share share = new Share(shareholderId, recoveredShare);
            return new VerifiableShare(share, commitment, null);
        } catch (SecretSharingException e) {
            logger.error("Failed to create recovery polynomial", e);
            return null;
        }
    }


    private int selectCorrectKey(Map<Integer, Integer> keys) {
        int max = 0;
        int key = -1;
        for (Map.Entry<Integer, Integer> entry : keys.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                key = entry.getKey();
            }
        }

        if (max <= oldThreshold)
            return -1;
        return key;
    }

    protected boolean haveCorrectState(byte[] selectedState, Map<Integer, Integer> states,
                                       int selectedStateHash) {
        if (selectedState == null)
            return false;
        Optional<Map.Entry<Integer, Integer>> max = states.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue));
        if (!max.isPresent()) {
            logger.info("I don't have correct common state");
            return false;
        }
        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() <= oldThreshold) {
            logger.info("I don't have correct common state");
            return false;
        }

        return selectedStateHash == entry.getKey();
    }

    private LinkedList<Share> deserializeBlindedShares(int from, byte[] serializedBlindedShares) {
        byte[] decryptedSerializedBlindedShares = confidentialityScheme.decryptData(processId, serializedBlindedShares);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(decryptedSerializedBlindedShares);
             ObjectInput in = new ObjectInputStream(bis)) {
            int nShares = in.readInt();
            LinkedList<Share> shares = new LinkedList<>();
            Share share;
            while (nShares-- > 0) {
                share = new Share();
                share.readExternal(in);
                shares.add(share);
            }
            return shares;
        } catch (IOException e) {
            logger.error("Failed to deserialize blinded shares from {}", from, e);
            return null;
        }
    }

    private MessageContext[] deserializeMessageContext(ObjectInput in) throws IOException, ClassNotFoundException {
        int size = in.readInt();
        if (size == -1)
            return null;
        MessageContext[] messageContexts = new MessageContext[size];
        for (int i = 0; i < size; i++) {
            int sender = in.readInt();
            int viewId = in.readInt();
            TOMMessageType type = TOMMessageType.fromInt(in.readInt());
            int session = in.readInt();
            int sequence = in.readInt();
            int operationId = in.readInt();
            int replyServer = in.readInt();
            int len = in.readInt();
            byte[] signature = null;
            if (len != -1) {
                signature = new byte[len];
                in.readFully(signature);
            }
            long timestamp = in.readLong();
            int regency = in.readInt();
            int leader = in.readInt();
            int consensusId = in.readInt();
            int numOfNonces = in.readInt();
            long seed = in.readLong();
            len = in.readInt();
            byte[] metadata = null;
            if (len > -1) {
                metadata = new byte[len];
                in.readFully(metadata);
            }
            len = in.readInt();
            Set<ConsensusMessage> proof = null;
            if (len != -1) {
                proof = new HashSet<>(len);
                while (len-- > 0) {
                    int from = -1;//in.readInt();
                    int number = in.readInt();
                    int epoch = in.readInt();
                    int paxosType = in.readInt();
                    int valueSize = in.readInt();
                    byte[] value = null;
                    if (valueSize != -1) {
                        value = new byte[valueSize];
                        in.readFully(value);
                    }

                    ConsensusMessage p = new ConsensusMessage(paxosType, number, epoch, from, value);
                    proof.add(p);
                }
            }

            TOMMessage firstInBatch = new TOMMessage();
            firstInBatch.rExternal(in);
            boolean lastInBatch = in.readBoolean();
            boolean noOp = in.readBoolean();
            //boolean readOnly = in.readBoolean();

            len = in.readInt();
            byte[] nonce;
            if (len != -1) {
                nonce = new byte[len];
                in.readFully(nonce);
            }

            MessageContext messageContext = new MessageContext(sender, viewId, type, session, sequence, operationId,
                    replyServer, signature, timestamp, numOfNonces, seed, regency, leader, consensusId,
                    proof, firstInBatch, noOp, metadata);
            if (lastInBatch)
                messageContext.setLastInBatch();
            messageContexts[i] = messageContext;
        }

        return messageContexts;
    }
}
