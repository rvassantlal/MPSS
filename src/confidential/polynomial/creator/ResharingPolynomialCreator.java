package confidential.polynomial.creator;

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

public class ResharingPolynomialCreator extends PolynomialCreator {

    ResharingPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator, ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication, PolynomialCreationListener creationListener) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF());
    }

    @Override
    ProposalMessage computeProposalMessage() {
        PolynomialContext oldContext = creationContext.getContexts()[0];
        PolynomialContext newContext = creationContext.getContexts()[1];
        int nPolynomials = creationContext.getnPolynomials();
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

        //generating polynomials and their commitments
        //(Additional witnesses are generated in Kate et al.scheme to valid point (0, 0) in Q and (i, 0) in each R
        Polynomial[] qs = new Polynomial[nPolynomials];
        Polynomial[][] rs = new Polynomial[nPolynomials][newN];
        Commitment[] qCommitments = new Commitment[nPolynomials];
        Commitment[][] rCommitments = new Commitment[nPolynomials][newN];
        for (int i = 0; i < nPolynomials; i++) {
            Polynomial q = new Polynomial(field, oldContext.getF(), BigInteger.ZERO, rndGenerator);
            qs[i] = q;
            qCommitments[i] = commitmentScheme.generateCommitments(q, BigInteger.ZERO);
            for (int j = 0; j < newN; j++) {
                Polynomial r = generateRecoveryPolynomialFor(newShareholders[j], oldContext.getF());
                rs[i][j] = r;
                rCommitments[i][j] = commitmentScheme.generateCommitments(r, newShareholders[j]);
            }
        }

        //generating encrypted shares
        Proposal[] proposals = new Proposal[nPolynomials];

        for (int i = 0; i < nPolynomials; i++) {
            Polynomial q = qs[i];
            Polynomial[] r = rs[i];
            Map<Integer, byte[]> shares = new HashMap<>(oldN);
            Commitment[] commitments = new Commitment[newN + 1];
            commitments[0] = qCommitments[i];
            System.arraycopy(rCommitments[i], 0, commitments, 1, newN);

            for (int o = 0; o < oldN; o++) {
                BigInteger[] vector = new BigInteger[newN];
                BigInteger shareholder = oldShareholders[o];
                for (int n = 0; n < newN; n++) {
                    vector[n] = q.evaluateAt(shareholder).add(r[n].evaluateAt(shareholder)).mod(field);
                }
                shares.put(oldServers[o], encryptVectorFor(oldServers[o], vector));
            }
            proposals[i] = new Proposal(shares, commitments);
        }

        return new ProposalMessage(
                creationContext.getId(),
                processId,
                proposals
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
            return confidentialityScheme.encryptDataFor(server, b);
        } catch (IOException e) {
            logger.error("Failed to encrypt vector", e);
            return null;
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
        Proposal[] proposals = proposalMessage.getProposals();
        int newN = creationContext.getContexts()[1].getMembers().length;
        Share share = new Share(confidentialityScheme.getMyShareholderId(), null);
        for (int i = 0; i < creationContext.getnPolynomials(); i++) {
            Proposal proposal = proposals[i];
            Map<Integer, BigInteger[]> points = decryptedPoints.get(i);
            if (points == null) {
                points = new HashMap<>(creationContext.getContexts()[0].getMembers().length);
                decryptedPoints.put(i, points);
            }
            byte[] encryptedVector = proposal.getPoints().get(processId);
            BigInteger[] decryptedVector = decryptVectorFor(processId, encryptedVector);
            if (decryptedVector == null) {
                logger.error("Failed to decrypt vector");
                return;
            }
            points.put(proposalMessage.getSender(), decryptedVector);
            Commitment[] commitments = proposal.getCommitments();

            for (int j = 0; j < newN; j++) {
                share.setShare(decryptedVector[j]);
                try {
                    Commitment commitment = commitmentScheme.sumCommitments(commitments[0], commitments[j + 1]);
                    if (!commitmentScheme.checkValidityWithoutPreComputation(share, commitment)) {
                        logger.warn("Proposal from {} is invalid", proposalMessage.getSender());
                        invalidProposals.add(proposalMessage.getSender());
                        return;
                    }
                } catch (SecretSharingException e) {
                    logger.error("Failed to sum commitments", e);
                }
            }
        }
    }
}
