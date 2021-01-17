package confidential.polynomial.creator;

import bftsmart.tom.util.TOMUtil;
import confidential.Metadata;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

public abstract class PolynomialCreator {
    protected Logger logger = LoggerFactory.getLogger("confidential");
    protected final PolynomialCreationContext creationContext;
    private final int quorumThreshold;
    private final int faultsThreshold;
    protected final BigInteger field;
    protected final SecureRandom rndGenerator;
    protected final CommitmentScheme commitmentScheme;
    private final InterServersCommunication serversCommunication;
    protected final int processId;
    protected final BigInteger shareholderId;
    private ProposalMessage myProposal;
    private final Map<Integer, ProposalMessage> proposals;
    protected final Map<Integer, Map<Integer, BigInteger[]>> decryptedPoints;
    protected final Map<Integer, ProposalMessage> finalProposalSet;
    private Map<Integer, byte[]> missingProposals;
    private boolean proposalSetProposed;
    protected final Set<Integer> validProposals;
    protected final Set<Integer> invalidProposals;
    protected final ServerConfidentialityScheme confidentialityScheme;
    private final PolynomialCreationListener creationListener;
    private final Set<Integer> newPolynomialRequestsFrom;
    private boolean iHaveSentNewPolyRequest;
    private long startTime;
    private ProcessedVotesMessage processedVotesMessage;
    private final List<VoteMessage> votes;
    private final Set<Integer> conflictList;
    private final Set<Integer> acceptList;
    private int d;

    PolynomialCreator(PolynomialCreationContext creationContext,
                      int processId, SecureRandom rndGenerator,
                      ServerConfidentialityScheme confidentialityScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener,
                      int n,
                      int f) {
        this.creationContext = creationContext;
        this.processId = processId;
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = confidentialityScheme.getField();
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = rndGenerator;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.serversCommunication = serversCommunication;
        this.creationListener = creationListener;

        this.quorumThreshold = n - f;
        this.faultsThreshold = f;

        int maxMessages = creationContext.getContexts()[0].getMembers().length;

        this.proposals = new HashMap<>(maxMessages);
        this.finalProposalSet = new HashMap<>(maxMessages);
        this.decryptedPoints = new HashMap<>(creationContext.getnPolynomials());
        this.validProposals = new HashSet<>(maxMessages);
        this.invalidProposals = new HashSet<>(maxMessages);
        this.newPolynomialRequestsFrom = new HashSet<>(maxMessages);
        this.votes = new ArrayList<>(maxMessages);
        this.acceptList = new HashSet<>(maxMessages);
        this.conflictList = new HashSet<>(maxMessages);
    }

    public PolynomialCreationContext getCreationContext() {
        return creationContext;
    }

    public void sendNewPolynomialCreationRequest() {
        if (iHaveSentNewPolyRequest)
            return;
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(
                processId, creationContext);
        int[] members = creationContext.getContexts()[0].getMembers();
        logger.debug("Sending NewPolynomialMessage to {} with id {}", Arrays.toString(members),
                creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.NEW_POLYNOMIAL, serialize(newPolynomialMessage),
                members);
        iHaveSentNewPolyRequest = true;
    }

    public void processNewPolynomialMessage(NewPolynomialMessage newPolynomialMessage) {
        if (newPolynomialRequestsFrom.size() >= quorumThreshold) {
            logger.debug("I already have n-f new polynomial Messages");
            return;
        }

        if (newPolynomialRequestsFrom.contains(newPolynomialMessage.getSender())) {
            logger.debug("Duplicated new polynomial request from {} with id {}",
                    newPolynomialMessage.getSender(), newPolynomialMessage.getId());
            return;
        }

        if (!creationContext.equals(newPolynomialMessage.getContext())) {
            logger.debug("New polynomial message from {} with id {} has different context",
                    newPolynomialMessage.getSender(),
                    newPolynomialMessage.getId());
            return;
        }

        newPolynomialRequestsFrom.add(newPolynomialMessage.getSender());

        logger.debug("I have {} requests to start creation of new polynomial with id {}",
                newPolynomialRequestsFrom.size(), creationContext.getId());

        if (newPolynomialRequestsFrom.size() >= quorumThreshold)
            generateAndSendProposal();
    }

    private void generateAndSendProposal() {
        logger.info("Creating new {} polynomial(s) with id {}", creationContext.getnPolynomials(),
                creationContext.getId());
        startTime = System.nanoTime();
        myProposal = computeProposalMessage();

        byte[] proposalHash = computeCryptographicHash(myProposal);
        PrivateKey signingKey = confidentialityScheme.getSigningPrivateKey();
        byte[] signature = TOMUtil.signMessage(signingKey, proposalHash);
        myProposal.setSignature(signature);

        int[] members = creationContext.getContexts()[0].getMembers();
        logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(members),
                creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL,
                serialize(myProposal), members);
    }

    abstract ProposalMessage computeProposalMessage();

    public void processProposal(ProposalMessage message) {
        if (proposals.containsKey(message.getSender())) {
            logger.warn("Duplicate proposal from {}. Ignoring.", message.getSender());
            return;
        }
        byte[] cryptHash = computeCryptographicHash(message);
        if (cryptHash == null) {
            return;
        }
        PublicKey signingPublicKey = confidentialityScheme.getSigningPublicKeyFor(message.getSender());
        if (!TOMUtil.verifySignature(signingPublicKey, cryptHash, message.getSignature())) {
            logger.warn("Server {} sent me a proposal with an invalid signature. Ignoring.", message.getSender());
            return;
        }
        message.setCryptographicHash(cryptHash);
        proposals.put(message.getSender(), message);
        if (processId == creationContext.getLeader()) {
            //validateProposal(message);
            //if (!proposalSetProposed && validProposals.size() > faultsThreshold)
            if (!proposalSetProposed && proposals.size() > faultsThreshold * 2)
                generateAndSendProposalSet();
        }
    }

    abstract void validateProposal(ProposalMessage proposalMessage);

    private byte[] computeCryptographicHash(ProposalMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(message.getSender());
            out.writeInt(message.getId());
            for (Proposal proposal : message.getProposals()) {
                int[] members = new int[proposal.getPoints().size()];
                int i = 0;
                Map<Integer, byte[]> points = proposal.getPoints();
                for (int member : points.keySet()) {
                    members[i++] = member;
                }
                Arrays.sort(members);
                for (int member : members) {
                    out.write(member);
                    out.write(points.get(member));
                }
                for (Commitment commitment : proposal.getCommitments()) {
                    commitment.writeExternal(out);
                }
            }
            out.flush();
            bos.flush();
            return TOMUtil.computeHash(bos.toByteArray());
        } catch (IOException e) {
            logger.error("Failed to create cryptographic hash of the proposal from {}", message.getSender(), e);
            return null;
        }
    }

    private void generateAndSendProposalSet() {
        int[] receivedNodes = new int[faultsThreshold * 2 + 1];
        byte[][] receivedProposalsHashes = new byte[faultsThreshold * 2 + 1][];
        int i = 0;

        for (Map.Entry<Integer, ProposalMessage> entry : proposals.entrySet()) {
            ProposalMessage proposal = entry.getValue();
            receivedNodes[i] = proposal.getSender();
            receivedProposalsHashes[i] = proposal.getCryptographicHash();

            int proposalHash = Arrays.hashCode(proposal.getCryptographicHash());
            finalProposalSet.put(proposalHash, proposal);
            i++;
        }

        ProposalSetMessage proposalSetMessage =  new ProposalSetMessage(
                creationContext.getId(),
                processId,
                receivedNodes,
                receivedProposalsHashes
        );
        int[] members = creationContext.getContexts()[0].getMembers();
        logger.debug("I'm leader and I'm proposing a proposal set with proposals from: {}",
                Arrays.toString(receivedNodes));
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                serialize(proposalSetMessage), members);

        proposalSetProposed = true;
    }

    boolean isValidShare(Commitment commitment, Share... shares) {
        boolean isValid = true;
        commitmentScheme.startVerification(commitment);
        for (Share share : shares) {
            if (!commitmentScheme.checkValidity(share, commitment)) {
                isValid = false;
                break;
            }
        }
        commitmentScheme.endVerification();
        return isValid;
    }

    public void processProposalSet(ProposalSetMessage message) {
        logger.info("Proposal set contains proposals from {}",
                Arrays.toString(message.getReceivedNodes()));
        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalSender = receivedNodes[i];
            ProposalMessage proposal = proposals.get(proposalSender);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", proposalSender,
                        creationContext.getId());
                if (missingProposals == null)
                    missingProposals = new HashMap<>();
                missingProposals.put(proposalSender, receivedProposals[i]);
                continue;
            }
            int proposalHash = Arrays.hashCode(proposal.getCryptographicHash());
            finalProposalSet.put(proposalHash, proposal);
            if (!Arrays.equals(proposal.getCryptographicHash(), receivedProposals[i])) {
                logger.warn("I received different proposal from {}", proposalSender);
                invalidProposals.add(proposal.getSender());
            }

            validateProposal(proposal);
        }

        if (missingProposals != null) {
            requestMissingProposals();
        } else
            sendVote();
    }

    private void sendVote() {
        byte[][] invalidProposalArray = new byte[invalidProposals.size()][];
        int i = 0;
        for (int invalidProposalSender : invalidProposals) {
            invalidProposalArray[i++] = proposals.get(invalidProposalSender).getCryptographicHash();
        }
        VoteMessage voteMessage = new VoteMessage(
                creationContext.getId(),
                processId,
                invalidProposalArray
        );
        logger.debug("Sending votes to {} with id {}", creationContext.getLeader(), creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_VOTE, serialize(voteMessage),
                creationContext.getLeader());
    }

    private void requestMissingProposals() {
        for (Map.Entry<Integer, byte[]> e : missingProposals.entrySet()) {
            MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage(
                    creationContext.getId(),
                    processId,
                    e.getValue()
            );
            logger.debug("Asking missing proposal to {} with id {}", e.getKey(), creationContext.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                    serialize(missingProposalRequestMessage), e.getKey());
        }
    }

    public void generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage(
                creationContext.getId(),
                processId,
                myProposal
        );
        logger.debug("Sending missing proposals to {} with id {}", message.getSender(), creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    public void processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage proposal = message.getMissingProposal();
        byte[] cryptHash = computeCryptographicHash(proposal);
        proposal.setCryptographicHash(cryptHash);
        proposals.put(proposal.getSender(), proposal);

        validateProposal(proposal);
        missingProposals.remove(proposal.getSender());
        if (missingProposals.isEmpty())
            sendVote();
    }

    public boolean processVote(VoteMessage message) {
        if (processedVotesMessage != null) {
            logger.debug("I have enough votes");
            return false;
        }
        votes.add(message);
        if (conflictList.contains(message.getSender())) {
            logger.debug("Server {} is in conflict list", message.getSender());
            return false;
        }
        boolean hasAccusation = false;
        for (byte[] accusation : message.getInvalidProposals()) {
            int proposalHash = Arrays.hashCode(accusation);
            ProposalMessage proposal = finalProposalSet.get(proposalHash);
            if (proposal != null) {
                logger.debug("Server {} accused {}", message.getSender(), proposal.getSender());
                hasAccusation = true;
                finalProposalSet.remove(proposalHash);
                decryptedPoints.remove(proposal.getSender());
                Map.Entry<Integer, ProposalMessage> senderProposal = null;
                for (Map.Entry<Integer, ProposalMessage> e : finalProposalSet.entrySet()) {
                    if (e.getValue().getSender() == message.getSender()) {
                        senderProposal = e;
                        break;
                    }
                }
                if (senderProposal != null) {
                    finalProposalSet.remove(senderProposal.getKey());
                    decryptedPoints.remove(senderProposal.getValue().getSender());
                }
                d++;
                conflictList.add(proposal.getSender());
                conflictList.add(message.getSender());
                acceptList.remove(proposal.getSender());
                acceptList.remove(message.getSender());
                break;
            }
        }
        if (!hasAccusation)
            acceptList.add(message.getSender());
        return acceptList.size() >= 2 * creationContext.getContexts()[0].getF() + 1 - d
                && acceptList.contains(creationContext.getLeader());
    }

    public void sendProcessedVotes() {
        processedVotesMessage = new ProcessedVotesMessage(
                creationContext.getId(),
                processId,
                votes
        );
        int[] members = creationContext.getContexts()[0].getMembers();
        logger.debug("Sending processed votes to {} with id {}", Arrays.toString(members), creationContext.getId());
        serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROCESSED_VOTES,
                new byte[]{(byte) Metadata.POLYNOMIAL_PROCESSED_VOTES.ordinal()},
                serialize(processedVotesMessage), members);
    }

    public boolean processVote(ProcessedVotesMessage message) {
        if (processedVotesMessage != null)
            return true;
        boolean terminated = false;
        for (VoteMessage vote : message.getVotes()) {
            terminated = processVote(vote);
        }
        return terminated;
    }

    public void deliverResult(int consensusId) {
        int nPolynomials = creationContext.getnPolynomials();
        int[] newServers = creationContext.getContexts()[1].getMembers();
        int newN = newServers.length;
        BigInteger[][] finalPoint = new BigInteger[nPolynomials][];
        Commitment[][] allCommitments = new Commitment[nPolynomials][newN + 1];

        for (int i = 0; i < nPolynomials; i++) {
            Map<Integer, BigInteger[]> parcelPoints = decryptedPoints.get(i);
            BigInteger[] points = new BigInteger[newN];
            Arrays.fill(points, BigInteger.ZERO);
            Commitment[][] commitments = new Commitment[newN + 1][parcelPoints.size()];

            int k = 0;
            for (Map.Entry<Integer, BigInteger[]> entry : parcelPoints.entrySet()) {
                BigInteger[] p = entry.getValue();
                ProposalMessage proposalMessage = proposals.get(entry.getKey());
                Proposal proposal = proposalMessage.getProposals()[i];

                commitments[0][k] = proposal.getCommitments()[0];
                for (int j = 0; j < newN; j++) {
                    points[j] = points[j].add(p[j]).mod(field);
                    commitments[j + 1][k] = proposal.getCommitments()[j + 1];
                }
                k++;
            }

            finalPoint[i] = points;
            for (int j = 0; j <= newN; j++) {
                try {
                    allCommitments[i][j] = commitmentScheme.sumCommitments(commitments[j]);
                } catch (SecretSharingException e) {
                    logger.error("Failed to sum valid commitments", e);
                }
            }
        }

        PolynomialPoint[] result = new PolynomialPoint[nPolynomials];
        for (int i = 0; i < nPolynomials; i++) {
            Map<Integer, Share> shares = new HashMap<>(newN);
            Map<Integer, Commitment> c = new HashMap<>(newN);
            Commitment[] allCommitment = allCommitments[i];
            c.put(-1, allCommitment[0]);
            for (int j = 0; j < newN; j++) {
                shares.put(newServers[j], new Share(shareholderId, finalPoint[i][j]));
                c.put(newServers[j], allCommitment[j + 1]);
            }
            result[i] = new PolynomialPoint(shares, c);
        }
        long endTime = System.nanoTime();
        double totalTime = (endTime - startTime) / 1_000_000.0;
        logger.info("{}:{} - Took {} ms to create {} polynomials", creationContext.getReason(),
                creationContext.getId(), totalTime, nPolynomials);
        creationListener.onPolynomialCreationSuccess(creationContext, consensusId, result);
    }

    public void startViewChange() {
        logger.debug("TODO:The leader {} is faulty. Changing view", creationContext.getLeader());
        throw new UnsupportedOperationException("TODO: Implement view change in " +
                "polynomial creation");
    }

    private byte[] serialize(PolynomialMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            message.writeExternal(out);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.warn("Polynomial message serialization failed", e);
            return null;
        }
    }
}
