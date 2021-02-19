package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.interServersCommunication.*;
import confidential.polynomial.creator.PolynomialCreator;
import confidential.polynomial.creator.PolynomialCreatorFactory;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomial implements InterServerMessageListener, Runnable {
    private final Logger logger = LoggerFactory.getLogger("polynomial_generation");
    private static final byte[] SEED = "confidential".getBytes();

    private final InterServersCommunication serversCommunication;
    private final SecureRandom rndGenerator;
    private final ServerConfidentialityScheme confidentialityScheme;
    private final ConcurrentHashMap<Integer, PolynomialCreator> polynomialCreators;
    private final Map<PolynomialCreationReason, PolynomialCreationListener> listeners;
    private final int processId;
    private final BlockingQueue<InterServerMessageHolder> pendingMessages;
    private final Lock entryLock;
    private final ExecutorService jobsProcessor;

    public DistributedPolynomial(ServerViewController svController, InterServersCommunication serversCommunication,
                                 ServerConfidentialityScheme confidentialityScheme) {
        this.serversCommunication = serversCommunication;
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = new SecureRandom(SEED);
        this.polynomialCreators = new ConcurrentHashMap<>();
        this.processId = svController.getStaticConf().getProcessId();
        this.listeners = new HashMap<>();
        this.pendingMessages = new LinkedBlockingQueue<>();
        entryLock = new ReentrantLock(true);
        serversCommunication.registerListener(this,
                InterServersMessageType.POLYNOMIAL_PROCESSED_VOTES
        );
        MessageListener polynomialMessageListener = new MessageListener(CommunicationTag.POLYNOMIAL) {
            @Override
            public void deliverMessage(InternalMessage message) {
                while (!pendingMessages.offer(new InterServerMessageHolder(message.getMessage(), null))){
                    logger.debug("Distributed polynomial pending message queue is full");
                }
            }
        };
        polynomialMessageListener.start();
        boolean isRegistered = serversCommunication.registerListener(polynomialMessageListener);
        if (!isRegistered)
            throw new IllegalStateException("Could not register polynomial message listener");

        jobsProcessor = Executors.newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
    }

    public int getProcessId() {
        return processId;
    }

    public void submitJob(Runnable job) {
        jobsProcessor.execute(job);
    }

    public void registerCreationListener(PolynomialCreationListener listener, PolynomialCreationReason reason) {
        entryLock.lock();
        listeners.put(reason, listener);
        entryLock.unlock();
    }

    public void createNewPolynomial(PolynomialCreationContext context) {
        try {
            entryLock.lock();
            PolynomialCreator polynomialCreator = polynomialCreators.get(context.getId());
            if (polynomialCreator != null && !polynomialCreator.getCreationContext().getReason().equals(context.getReason())) {
                logger.debug("Polynomial with id {} is already being created for different reason", context.getId());
                return;
            }

            if (polynomialCreator == null) {
                polynomialCreator = createNewPolynomialCreator(context);
                if (polynomialCreator == null)
                    return;
            }
            polynomialCreator.sendNewPolynomialCreationRequest();
        } finally {
            entryLock.unlock();
        }
    }

    private PolynomialCreator createNewPolynomialCreator(PolynomialCreationContext context) {
        PolynomialCreator polynomialCreator = PolynomialCreatorFactory.getInstance().getNewCreatorFor(
                context,
                processId,
                rndGenerator,
                confidentialityScheme,
                serversCommunication,
                listeners.get(context.getReason()),
                this
        );

        if (polynomialCreator == null)
            return null;

        polynomialCreators.put(context.getId(), polynomialCreator);
        return polynomialCreator;
    }

    @Override
    public void messageReceived(InterServerMessageHolder message) {

        while (!pendingMessages.offer(message)){
            logger.debug("Distributed polynomial pending message queue is full");
        }
    }

    @Override
    public void run() {
        ExecutorService executorService = Executors.newFixedThreadPool(
                Configuration.getInstance().getShareProcessingThreads());
        while (true) {
            try {
                InterServerMessageHolder message = pendingMessages.take();
                entryLock.lock();
                PolynomialMessage polynomialMessage = null;
                InterServersMessageType type = null;
                try (ByteArrayInputStream bis = new ByteArrayInputStream(message.getSerializedMessage());
                     ObjectInput in = new ObjectInputStream(bis)) {
                    type = InterServersMessageType.getType(in.read());
                    switch (type) {
                        case NEW_POLYNOMIAL:
                            polynomialMessage = new NewPolynomialMessage();
                            break;
                        case POLYNOMIAL_PROPOSAL:
                            polynomialMessage = new ProposalMessage();
                            break;
                        case POLYNOMIAL_PROPOSAL_SET:
                            polynomialMessage = new ProposalSetMessage();
                            break;
                        case POLYNOMIAL_PROCESSED_VOTES:
                            polynomialMessage = new ProcessedVotesMessage();
                            break;
                        case POLYNOMIAL_VOTE:
                            polynomialMessage = new VoteMessage();
                            break;
                        case POLYNOMIAL_REQUEST_MISSING_PROPOSALS:
                            polynomialMessage = new MissingProposalRequestMessage();
                            break;
                        case POLYNOMIAL_MISSING_PROPOSALS:
                            polynomialMessage = new MissingProposalsMessage();
                            break;
                        default:
                            logger.warn("Unknown polynomial message type {}", type);
                            continue;
                    }
                    polynomialMessage.readExternal(in);

                } catch (IOException | ClassNotFoundException e) {
                    logger.error("Failed to deserialize polynomial message of type", e);
                }
                if (polynomialMessage == null) {
                    logger.debug("Polynomial message is null");
                    continue;
                }
                PolynomialCreator polynomialCreator = polynomialCreators.get(polynomialMessage.getId());
                if (polynomialCreator == null && polynomialMessage instanceof NewPolynomialMessage) {
                    NewPolynomialMessage newPolynomialMessage = (NewPolynomialMessage) polynomialMessage;
                    logger.debug("There is no active polynomial creation with id {}", newPolynomialMessage.getId());
                    logger.debug("Creating new polynomial creator for id {} and reason {}", newPolynomialMessage.getId(),
                            newPolynomialMessage.getContext().getReason());
                    polynomialCreator = createNewPolynomialCreator(newPolynomialMessage.getContext());
                }
                if (polynomialCreator == null) {
                    logger.debug("There is no active polynomial creation with id {}", polynomialMessage.getId());
                    continue;
                }
                PolynomialMessage finalPolynomialMessage = polynomialMessage;
                InterServersMessageType finalType = type;
                int cid = message.getMessageContext() == null ? -1 : message.getMessageContext().getConsensusId();
                PolynomialCreator finalPolynomialCreator = polynomialCreator;
                executorService.execute(() -> finalPolynomialCreator.messageReceived(finalType,
                        finalPolynomialMessage, cid));
            } catch (InterruptedException e) {
                logger.error("Something went wrong", e);
                break;
            } finally {
                entryLock.unlock();
            }
        }
        executorService.shutdown();
        logger.debug("Exiting Distributed Polynomial");
    }

    public void removePolynomialCreator(int id) {
        polynomialCreators.remove(id);
    }
}
