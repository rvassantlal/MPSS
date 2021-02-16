package confidential.statemanagement.resharing;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ReconstructionCompleted;
import confidential.statemanagement.privatestate.receiver.BlindedStateHandler;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ResharingBlindedStateHandler extends BlindedStateHandler {

    public ResharingBlindedStateHandler(ServerViewController svController, int serverPort, int f, int quorum,
                                        int stateSenderReplica, ServerConfidentialityScheme confidentialityScheme,
                                        ReconstructionCompleted reconstructionListener) {
        super(svController, serverPort, f, quorum, stateSenderReplica, confidentialityScheme,
                reconstructionListener);
    }

    @Override
    protected Share[] reconstructBlindedShares(int from, byte[][] shares) {
        BigInteger shareholder = confidentialityScheme.getShareholder(from);
        Share[] result = new Share[shares.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = new Share(shareholder,
                    new BigInteger(confidentialityScheme.decryptData(from, shares[i])));
        }
        return result;
    }

    @Override
    protected Iterator<VerifiableShare> reconstructShares(int nShares,
                                                          Map<Integer, Share[]> allBlindedShares,
                                                          Map<BigInteger, Commitment[]> allBlindedCommitments) {
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        CountDownLatch latch = new CountDownLatch(nShares);

        VerifiableShare[] recoveredShares = new VerifiableShare[nShares];
        Integer[] servers = new Integer[allBlindedShares.size()];
        BigInteger[] shareholders = new BigInteger[allBlindedCommitments.size()];
        int k = 0;
        for (Integer server : allBlindedShares.keySet()) {
            servers[k++] = server;
        }

        k = 0;
        for (BigInteger shareholder : allBlindedCommitments.keySet()) {
            shareholders[k++] = shareholder;
        }

        for (int i = 0; i < nShares; i++) {
            Map<Integer, Share> blindedShares = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment> commitments = new HashMap<>(stillValidSenders.size());
            Map<BigInteger, Commitment> blindingCommitments = new HashMap<>(stillValidSenders.size());
            int index = i * 2;
            for (Integer server : servers) {
                blindedShares.put(server, allBlindedShares.get(server)[i]);
            }
            for (BigInteger shareholder : shareholders) {
                commitments.put(shareholder, allBlindedCommitments.get(shareholder)[index]);
                blindingCommitments.put(shareholder, allBlindedCommitments.get(shareholder)[index + 1]);
            }
            int finalI = i;
            executorService.execute(() -> {
                VerifiableShare vs = recoverShare(blindedShares, commitments, blindingCommitments);
                if (vs == null) {
                    return;
                }
                recoveredShares[finalI] = vs;
                latch.countDown();
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();
        LinkedList<VerifiableShare> result = new LinkedList<>();
        for (VerifiableShare refreshedShare : recoveredShares) {
            if (refreshedShare == null)
                return null;
            result.add(refreshedShare);
        }
        return result.iterator();
    }

    private VerifiableShare recoverShare(Map<Integer, Share> blindedShares, Map<BigInteger, Commitment> commitments,
                                         Map<BigInteger, Commitment> blindingCommitments) {
        try {
            int corruptedServers = this.corruptedServers.get();
            Share[] recoveringShares = new Share[f + (corruptedServers < f ? 2 : 1)];
            Commitment combinedCommitments = commitmentScheme.combineCommitments(commitments);
            Commitment combinedBlindingCommitments = commitmentScheme.combineCommitments(blindingCommitments);
            Commitment verificationCommitments = commitmentScheme.sumCommitments(combinedCommitments,
                    combinedBlindingCommitments);
            Map<BigInteger, Commitment> validCommitments = new HashMap<>(f);

            int j = 0;
            for (Map.Entry<Integer, Share> entry : blindedShares.entrySet()) {
                int server = entry.getKey();
                BigInteger shareholder = confidentialityScheme.getShareholder(server);
                if (commitmentScheme.checkValidityWithoutPreComputation(entry.getValue(), verificationCommitments)) {
                    recoveringShares[j++] = entry.getValue();
                    if (validCommitments.size() <= f) {
                        validCommitments.put(shareholder, commitments.get(shareholder));
                    }
                } else {
                    logger.error("Server {} sent me invalid share", server);
                    commitments.remove(shareholder);
                    blindingCommitments.remove(shareholder);
                    this.corruptedServers.incrementAndGet();
                    stillValidSenders.remove(server);
                }
                if (j == recoveringShares.length)
                    break;
            }

            BigInteger shareNumber = interpolationStrategy.interpolateAt(shareholderId, recoveringShares);
            Commitment commitment = commitmentScheme.recoverCommitment(shareholderId, validCommitments);

            Share share = new Share(shareholderId, shareNumber);
            return new VerifiableShare(share, commitment, null);
        } catch (SecretSharingException e) {
            logger.error("Failed to a recover share", e);
            return null;
        }
    }
}
