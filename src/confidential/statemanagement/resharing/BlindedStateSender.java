package confidential.statemanagement.resharing;

import bftsmart.communication.SystemMessage;
import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.ConfidentialData;
import confidential.Configuration;
import confidential.polynomial.PolynomialPoint;
import confidential.server.Request;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.BlindedApplicationState;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.utils.HashThread;
import confidential.statemanagement.utils.PublicDataSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BlindedStateSender extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final ServerViewController svController;
    private final int processId;
    private final BigInteger field;
    private final int unSecureServerPort;
    private final int[] receivers;
    private final DefaultApplicationState state;
    private final PolynomialPoint[] blindingShares;
    private final HashThread commonStateHashThread;
    private final HashThread[] commitmentHashThread;
    private final boolean iAmStateSender;
    private final ServerConfidentialityScheme confidentialityScheme;

    public BlindedStateSender(ServerViewController svController, BigInteger field,
                              int stateReceiverPort, int[] receivers,
                              DefaultApplicationState state, PolynomialPoint[] blindingShares,
                              ServerConfidentialityScheme confidentialityScheme, boolean iAmStateSender) throws Exception {
        super("State Sender Thread");
        this.svController = svController;
        this.processId = svController.getStaticConf().getProcessId();
        this.field = field;
        this.unSecureServerPort = stateReceiverPort;
        this.receivers = receivers;
        this.state = state;
        this.blindingShares = blindingShares;
        this.confidentialityScheme = confidentialityScheme;
        this.iAmStateSender = iAmStateSender;
        this.commonStateHashThread = new HashThread();
        if (Configuration.getInstance().getVssScheme().equals("1")) {//linear scheme
            commitmentHashThread = new HashThread[receivers.length];
            for (int i = 0; i < receivers.length; i++) {
                commitmentHashThread[i] = new HashThread();
            }
        } else {
            this.commitmentHashThread = null;
        }
    }

    @Override
    public void run() {
        logger.debug("Generating blinded state");
        long t1, t2;
        t1 = System.nanoTime();
        BlindedApplicationState[] blindedStates = createBlindedState(blindingShares, state);
        t2 = System.nanoTime();
        if (blindedStates == null) {
            logger.error("Failed to generate blinded application state. Exiting state sender thread.");
            return;
        }
        double blindedStateTime = (t2 - t1) / 1_000_000.0;
        logger.info("Took {} ms to compute blinded state", blindedStateTime);
        if (!iAmStateSender) {
            byte[] commonState = blindedStates[0].getCommonState();
            commonStateHashThread.setData(commonState);
            commonStateHashThread.start();
            commonStateHashThread.update(0, commonState.length);
            commonStateHashThread.update(-1, -1);

            if (commitmentHashThread != null) {
                for (int i = 0; i < receivers.length; i++) {
                    byte[] commitments = blindedStates[i].getCommitments();
                    commitmentHashThread[i].setData(commitments);
                    commitmentHashThread[i].start();
                    commitmentHashThread[i].update(0, commitments.length);
                    commitmentHashThread[i].update(-1, -1);
                }
            }
        }

        byte[][] serializedBlindedShares = new byte[receivers.length][];
        int[] nBytes = new int[receivers.length];
        t1 = System.nanoTime();
        for (int i = 0; i < receivers.length; i++) {
            serializedBlindedShares[i] = serializeBlindedSharesFor(blindedStates[i].getShares(), receivers[i]);
            if (serializedBlindedShares[i] == null) {
                logger.error("Failed to serialized blinded shares");
                return;
            }
            nBytes[i] = serializedBlindedShares[i].length;
        }
        t2 = System.nanoTime();
        double blindedSharesSerializationTime = (t2 - t1) / 1_000_000.0;
        logger.info("Took {} ms to serialize {} blinded shares ({} bytes)", blindedSharesSerializationTime,
                blindedStates[0].getShares().size(), Arrays.toString(nBytes));

        PublicDataSender[] publicDataSenders = new PublicDataSender[receivers.length];

        for (int i = 0; i < receivers.length; i++) {
            String receiverIp = svController.getCurrentView().getAddress(receivers[i]).getAddress().getHostAddress();
            int port = unSecureServerPort + receivers[i];
            publicDataSenders[i] = new PublicDataSender(receiverIp, port , processId, 3);
            publicDataSenders[i].start();
            publicDataSenders[i].sendData(serializedBlindedShares[i]);
        }

        byte[][] commitments = null;
        if (!iAmStateSender && commitmentHashThread != null) {
            commitments = new byte[receivers.length][];
            for (int i = 0; i < receivers.length; i++) {
                commitments[i] = commitmentHashThread[i].getHash();
            }
        }
        boolean sameCommitments = commitments != null;
        logger.info("Sending {} bytes of commitments", blindedStates[0].getCommitments().length);

        for (int i = 0; i < receivers.length; i++) {
            if (!sameCommitments) {
                byte[] c = blindedStates[i].getCommitments();
                publicDataSenders[i].sendData(c);
            } else {
                publicDataSenders[i].sendData(commitments[i]);
            }
        }


        byte[] commonState;
        if (iAmStateSender) {
            commonState = blindedStates[0].getCommonState();
        } else {
            commonState = commonStateHashThread.getHash();
        }
        logger.info("Sending {} bytes of common state", commonState.length);
        for (PublicDataSender publicDataSender : publicDataSenders) {
            publicDataSender.sendData(commonState);
        }
        logger.debug("Exiting state sender thread");
    }

    private BlindedApplicationState[] createBlindedState(PolynomialPoint[] blindingShare, DefaultApplicationState state) {

        try (ByteArrayOutputStream bosCommonState = new ByteArrayOutputStream();
             ObjectOutput outCommonState = new ObjectOutputStream(bosCommonState)) {

            LinkedList<VerifiableShare> sharesToSend = new LinkedList<>();

            CommandsInfo[] log = state.getMessageBatches();

            outCommonState.writeInt(state.getLastCheckpointCID());
            outCommonState.writeInt(state.getLastCID());

            outCommonState.writeInt(log == null ? -1 : log.length);

            if (log != null) {
                serializeLog(log, outCommonState, sharesToSend);
            }

            ConfidentialSnapshot snapshot = null;
            if (state.hasState()) {
                snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
            }

            if (snapshot != null) {
                outCommonState.writeBoolean(true);
                serializeSnapshot(snapshot, outCommonState, sharesToSend);
            } else {
                outCommonState.writeBoolean(false);
            }

            RecoveryContribution[] recoveryContributions = processShares(sharesToSend, blindingShare);
            bosCommonState.flush();
            outCommonState.flush();
            byte[] commonStateBytes = bosCommonState.toByteArray();

            BlindedApplicationState[] results = new BlindedApplicationState[receivers.length];
            for (int i = 0; i < receivers.length; i++) {
                try (ByteArrayOutputStream bosCommitments = new ByteArrayOutputStream();
                     ObjectOutput outCommitments = new ObjectOutputStream(bosCommitments)) {
                    RecoveryContribution recoveryContribution = recoveryContributions[i];
                    LinkedList<Share> blindedShares = new LinkedList<>();

                    VerifiableShare[] shares = recoveryContribution.getShares();
                    Commitment[] rCommitments = recoveryContribution.getRCommitments();
                    for (int j = 0; j < shares.length; j++) {
                        vss.Utils.writeCommitment(shares[j].getCommitments(), outCommitments);
                        vss.Utils.writeCommitment(rCommitments[j], outCommitments);
                        blindedShares.offer(shares[j].getShare());
                    }
                    bosCommitments.flush();
                    outCommitments.flush();
                    byte[] commitmentsBytes = bosCommitments.toByteArray();
                    results[i] = new BlindedApplicationState(
                            commonStateBytes,
                            blindedShares,
                            commitmentsBytes
                    );
                }
            }
            return results;
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to create Blinded State", e);
            return null;
        }
    }

    private RecoveryContribution[] processShares(LinkedList<VerifiableShare> sharesToSend,
                                                 PolynomialPoint[] blindingShares) throws InterruptedException, IOException {
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());

        int nShares = sharesToSend.size();
        VerifiableShare[][] blindedSharesToSend = new VerifiableShare[receivers.length][nShares];
        Commitment[][] rCommitments = new Commitment[receivers.length][nShares];

        Iterator<VerifiableShare> it = sharesToSend.iterator();
        CountDownLatch sharesProcessedCounter = new CountDownLatch(nShares);
        int nBlindingPolynomials = blindingShares.length;
        for (int i = 0; i < nShares; i++) {
            int finalI = i;
            VerifiableShare vs = it.next();
            PolynomialPoint blindingShare = blindingShares[i % nBlindingPolynomials];
            executorService.execute(() -> {
                try {
                    Commitment commitment = vs.getCommitments();
                    Share share = vs.getShare();
                    for (int j = 0; j < receivers.length; j++) {
                        int receiver = receivers[j];
                        Commitment blindedCommitment = confidentialityScheme.getCommitmentScheme()
                                .sumCommitments(blindingShare.getCommitments(-1), commitment);
                        Commitment rCommitment = blindingShare.getCommitments(receiver);
                        BigInteger nBs = share.getShare().add(blindingShare.getShares(receiver).getShare()).mod(field);
                        Share bs = new Share(vs.getShare().getShareholder(), nBs);
                        VerifiableShare verifiableShare = new VerifiableShare(bs, blindedCommitment, null);
                        rCommitments[j][finalI] = rCommitment;
                        blindedSharesToSend[j][finalI] = verifiableShare;
                    }
                    sharesProcessedCounter.countDown();
                } catch (SecretSharingException e) {
                    logger.error("Failed to create blinded share.", e);
                }
            });
        }
        sharesProcessedCounter.await();
        executorService.shutdown();
        RecoveryContribution[] recoveryContributions = new RecoveryContribution[receivers.length];
        for (int i = 0; i < receivers.length; i++) {
            VerifiableShare[] verifiableShares = blindedSharesToSend[i];
            Commitment[] commitments = rCommitments[i];
            recoveryContributions[i] = new RecoveryContribution(verifiableShares, commitments);
        }
        return recoveryContributions;
    }

    private void serializeSnapshot(ConfidentialSnapshot snapshot, ObjectOutput outCommonState,
                                   LinkedList<VerifiableShare> sharesToSend) throws IOException {
        byte[] b;
        outCommonState.writeInt(snapshot.getPlainData() == null ? -1 : snapshot.getPlainData().length);
        if (snapshot.getPlainData() != null)
            outCommonState.write(snapshot.getPlainData());
        outCommonState.writeInt(snapshot.getShares() == null ? -1 : snapshot.getShares().length);
        if (snapshot.getShares() != null) {
            for (ConfidentialData share : snapshot.getShares()) {
                b = share.getShare().getSharedData();
                outCommonState.writeInt(b == null ? -1 : b.length);
                if (b != null)
                    outCommonState.write(b);
                sharesToSend.add(share.getShare());
            }
        }
    }

    private void serializeLog(CommandsInfo[] log, ObjectOutput outCommonState,
                              LinkedList<VerifiableShare> sharesToSend) throws IOException {
        byte[] b;
        for (CommandsInfo commandsInfo : log) {
            byte[][] commands = commandsInfo.commands;
            MessageContext[] msgCtx = commandsInfo.msgCtx;
            serializeMessageContext(outCommonState, msgCtx);
            outCommonState.writeInt(commands.length);
            for (byte[] command : commands) {
                Request request = Request.deserialize(command);
                if (request == null || request.getShares() == null) {
                    outCommonState.writeInt(-1);
                    outCommonState.writeInt(command.length);
                    outCommonState.write(command);
                } else {
                    outCommonState.writeInt(request.getShares().length);
                    for (ConfidentialData share : request.getShares()) {
                        b = share.getShare().getSharedData();
                        outCommonState.writeInt(b == null ? -1 : b.length);
                        if (b != null)
                            outCommonState.write(b);
                        sharesToSend.add(share.getShare());
                    }
                    request.setShares(null);
                    b = request.serialize();
                    if (b == null) {
                        logger.debug("Failed to serialize blinded Request");
                        return;
                    }
                    outCommonState.writeInt(b.length);
                    outCommonState.write(b);
                }
            }
        }
    }

    private byte[] serializeBlindedSharesFor(LinkedList<Share> blindedShares, int server) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(blindedShares.size());
            for (Share share : blindedShares) {
                share.writeExternal(out);
            }
            out.flush();
            bos.flush();
            byte[] serializedBlindedShares = bos.toByteArray();
            return confidentialityScheme.encryptDataFor(server, serializedBlindedShares);
        } catch (IOException e) {
            logger.error("Failed to serialize and encrypt Shares for {}", server, e);
            return null;
        }
    }

    private void serializeMessageContext(ObjectOutput out, MessageContext[] msgCtx) throws IOException {
        out.writeInt(msgCtx == null ? -1 : msgCtx.length);
        if (msgCtx == null)
            return;
        for (MessageContext ctx : msgCtx) {
            out.writeInt(ctx.getSender());
            out.writeInt(ctx.getViewID());
            out.writeInt(ctx.getType().ordinal());
            out.writeInt(ctx.getSession());
            out.writeInt(ctx.getSequence());
            out.writeInt(ctx.getOperationId());
            out.writeInt(ctx.getReplyServer());
            out.writeInt(ctx.getSignature() == null ? -1 : ctx.getSignature().length);
            if (ctx.getSignature() != null)
                out.write(ctx.getSignature());

            out.writeLong(ctx.getTimestamp());
            out.writeInt(ctx.getRegency());
            out.writeInt(ctx.getLeader());
            out.writeInt(ctx.getConsensusId());
            out.writeInt(ctx.getNumOfNonces());
            out.writeLong(ctx.getSeed());
            out.writeInt(ctx.getMetadata() == null ? -1 : ctx.getMetadata().length);
            if (ctx.getMetadata() != null) {
                out.write(ctx.getMetadata());
            }
            out.writeInt(ctx.getProof() == null ? -1 : ctx.getProof().size());
            if (ctx.getProof() != null) {
                List<ConsensusMessage> orderedProf = new ArrayList<>(ctx.getProof());
                orderedProf.sort(Comparator.comparingInt(SystemMessage::getSender));
                for (ConsensusMessage proof : orderedProf) {
                    //logger.info("{} {} {} {} {}", proof.getSender(), proof.getNumber(),
                    //        proof.getEpoch(), proof.getType(), proof.getValue());
                    //out.writeInt(proof.getSender());
                    out.writeInt(proof.getNumber());
                    out.writeInt(proof.getEpoch());
                    out.writeInt(proof.getType());

                    out.writeInt(proof.getValue() == null ? -1 : proof.getValue().length);
                    if (proof.getValue() != null)
                        out.write(proof.getValue());
                    /*logger.debug("{}", proof.getProof());*/
                }
            }
            ctx.getFirstInBatch().wExternal(out);
            out.writeBoolean(ctx.isLastInBatch());
            out.writeBoolean(ctx.isNoOp());
            //out.writeBoolean(ctx.readOnly);

            out.writeInt(ctx.getNonces() == null ? -1 : ctx.getNonces().length);
            if (ctx.getNonces() != null)
                out.write(ctx.getNonces());
        }

    }
}
