package confidential.polynomial.creator;

import confidential.Configuration;
import confidential.Utils;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import org.bouncycastle.util.Arrays;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ResharingPolynomialCreator extends PolynomialCreator {
    private final Lock vectorEncryptionLock;

    ResharingPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator, ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication, PolynomialCreationListener creationListener) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF());
        this.vectorEncryptionLock = new ReentrantLock(true);
    }

    @Override
    ProposalMessage computeProposalMessage() {
        PolynomialContext oldContext = creationContext.getContexts()[0];
        PolynomialContext newContext = creationContext.getContexts()[1];
        int[] oldServers = oldContext.getMembers();
        int[] newServers = newContext.getMembers();
        int oldN = oldServers.length;
        int newN = newServers.length;
        BigInteger[] newShareholders = new BigInteger[newN];
        BigInteger[] oldShareholders = new BigInteger[oldN];
        for (int i = 0; i < newN; i++) {
            newShareholders[i] = confidentialityScheme.getShareholder(newServers[i]);
        }
        for (int i = 0; i < oldN; i++) {
            oldShareholders[i] = confidentialityScheme.getShareholder(oldServers[i]);
        }

        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        CountDownLatch latch = new CountDownLatch(newN + 1);

        Polynomial[] polynomials = new Polynomial[newN + 1];
        Commitment[] commitments = new Commitment[newN + 1];
        for (int i = 0; i <= newN; i++) {
            Polynomial polynomial;
            BigInteger shareholder;
            if (i == 0) {
                shareholder = BigInteger.ZERO;
                polynomial = new Polynomial(field, oldContext.getF(), shareholder, rndGenerator);
            } else {
                shareholder = newShareholders[i - 1];
                polynomial = generateRecoveryPolynomialFor(shareholder, oldContext.getF());
            }
            polynomials[i] = polynomial;
            int finalI = i;
            executorService.execute(() -> {
                commitments[finalI] = commitmentScheme.generateCommitments(polynomial, shareholder);
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        executorService.shutdown();

        //generating encrypted shares
        Map<Integer, byte[]> shares = new HashMap<>(oldN);
        Polynomial q = polynomials[0];
        for (int o = 0; o < oldN; o++) {
            BigInteger[] vector = new BigInteger[newN];
            BigInteger shareholder = oldShareholders[o];
            for (int n = 0; n < newN; n++) {
                vector[n] = q.evaluateAt(shareholder).add(polynomials[n + 1].evaluateAt(shareholder)).mod(field);
            }
            shares.put(oldServers[o], encryptVectorFor(oldServers[o], vector));
        }
        Proposal proposal = new Proposal(shares, commitments);

        return new ProposalMessage(
                creationContext.getId(),
                processId,
                proposal
        );
    }

    private byte[] encryptVectorFor(int server, BigInteger[] vector) {
        int totalBytes = vector.length * 4 + 4;
        for (BigInteger v : vector) {
            totalBytes += v.toByteArray().length;
        }
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream(totalBytes)) {
            bos.write(Utils.toBytes(vector.length));
            for (BigInteger v : vector) {
                bos.write(Utils.toBytes(v.toByteArray().length));
                bos.write(v.toByteArray());
            }
            bos.flush();
            byte[] b = bos.toByteArray();
            vectorEncryptionLock.lock();
            return confidentialityScheme.encryptDataFor(server, b);
        } catch (IOException e) {
            logger.error("Failed to encrypt vector", e);
            return null;
        } finally {
            vectorEncryptionLock.unlock();
        }
    }

    private BigInteger[] decryptVectorFor(int server, byte[] encryptedVector) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(confidentialityScheme
                .decryptData(server, encryptedVector))) {
            int nValues = Utils.toNumber(Utils.readNBytes(4, bis));
            BigInteger[] vector = new BigInteger[nValues];
            for (int i = 0; i < nValues; i++) {
                int len = Utils.toNumber(Utils.readNBytes(4, bis));
                vector[i] = new BigInteger(Utils.readNBytes(len, bis));
            }
            return vector;
        } catch (IOException e) {
            logger.error("Failed to decrypted vector", e);
            return null;
        }
    }

    private Polynomial generateRecoveryPolynomialFor(BigInteger shareholder, int degree) {
        Polynomial tempPolynomial = new Polynomial(field, degree, BigInteger.ZERO, rndGenerator);
        BigInteger independentTerm = tempPolynomial.evaluateAt(shareholder).negate();

        BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
        BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
                tempCoefficients.length - tempPolynomial.getDegree() - 1, tempCoefficients.length - 1);
        return new Polynomial(field, independentTerm, coefficients);
    }

    @Override
    void validateProposal(ProposalMessage proposalMessage) {
        Proposal proposal = proposalMessage.getProposal();
        int newN = creationContext.getContexts()[1].getMembers().length;

        byte[] encryptedVector = proposal.getPoints().get(processId);
        BigInteger[] decryptedVector = decryptVectorFor(processId, encryptedVector);
        if (decryptedVector == null) {
            logger.error("Failed to decrypt vector");
            return;
        }
        decryptedPoints.put(proposalMessage.getSender(), decryptedVector);

        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        CountDownLatch latch = new CountDownLatch(newN);
        Commitment[] commitments = proposal.getCommitments();

        Commitment qCommitment = commitments[0];
        for (int i = 0; i < newN; i++) {
            Commitment rCommitment = commitments[i + 1];
            Share share = new Share(shareholderId, decryptedVector[i]);
            executorService.submit(() -> {
                    try {
                        Commitment commitment = commitmentScheme.sumCommitments(qCommitment, rCommitment);
                        if (!commitmentScheme.checkValidityWithoutPreComputation(share, commitment)) {
                            logger.warn("Proposal from {} is invalid", proposalMessage.getSender());
                            invalidProposals.add(proposalMessage.getSender());
                            latch.countDown();
                            return;
                        }
                    } catch (SecretSharingException e) {
                        logger.error("Failed to sum commitments", e);
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
    }
}
