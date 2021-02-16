package confidential.statemanagement.resharing;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.Configuration;
import confidential.polynomial.PolynomialPoint;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.privatestate.sender.BlindedShares;
import confidential.statemanagement.privatestate.sender.BlindedStateSender;
import confidential.statemanagement.privatestate.sender.StateSeparationListener;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ResharingBlindedStateSender extends BlindedStateSender {

    public ResharingBlindedStateSender(ServerViewController svController, DefaultApplicationState applicationState,
                                       int blindedStateReceiverPort, ServerConfidentialityScheme confidentialityScheme,
                                       boolean iAmStateSender, StateSeparationListener stateSeparationListener,
                                       int... blindedStateReceivers) {
        super(svController, applicationState, blindedStateReceiverPort, confidentialityScheme, iAmStateSender,
                stateSeparationListener, blindedStateReceivers);
    }

    @Override
    protected BlindedShares[] computeBlindedShares(LinkedList<Share> shares, LinkedList<Commitment> commitments,
                                                 PolynomialPoint[] blindingShares) {
        logger.debug("Computing blinded shares");
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        int nShares = shares.size();
        byte[][][] resultingShares = new byte[blindedStateReceivers.length][nShares][];
        Commitment[][] resultingCommitments = new Commitment[blindedStateReceivers.length][nShares * 2];

        Iterator<Share> shareIterator = shares.iterator();
        Iterator<Commitment> commitmentsIterator = commitments.iterator();
        CountDownLatch latch = new CountDownLatch(nShares);
        BigInteger field = confidentialityScheme.getField();
        CommitmentScheme commitmentScheme = confidentialityScheme.getCommitmentScheme();
        for (int i = 0; i < nShares; i++) {
            PolynomialPoint blindingShare = blindingShares[i];
            Share share = shareIterator.next();
            Commitment commitment = commitmentsIterator.next();
            int finalI = i;
            executorService.execute(() -> {
                try {
                    Commitment blindedCommitment = commitmentScheme.sumCommitments(commitment,
                            blindingShare.getCommitments(-1));
                    int index = finalI * 2;
                    for (int j = 0; j < blindedStateReceivers.length; j++) {
                        int receiver = blindedStateReceivers[j];
                        BigInteger blindedShare = share.getShare().add(blindingShare.getShares(receiver)
                                .getShare()).mod(field);
                        resultingCommitments[j][index] = blindedCommitment;
                        resultingCommitments[j][index + 1] = blindingShare.getCommitments(receiver);
                        resultingShares[j][finalI] = confidentialityScheme.encryptDataFor(receiver,
                                blindedShare.toByteArray());
                    }
                } catch (SecretSharingException e) {
                    logger.error("Failed to create blinded share", e);
                }
                latch.countDown();
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();
        BlindedShares[] result = new BlindedShares[blindedStateReceivers.length];
        for (int i = 0; i < blindedStateReceivers.length; i++) {
            result[i] = new BlindedShares(resultingShares[i], resultingCommitments[i]);
        }

        return result;
    }
}
