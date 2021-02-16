package confidential.polynomial;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomialManager implements PolynomialCreationListener {
    private final Logger logger = LoggerFactory.getLogger("polynomial_generation");
    private int internalSequenceNumber;
    private final DistributedPolynomial distributedPolynomial;
    private final ResharingPolynomialListener resharingListener;
    private final ConcurrentMap<Integer, ResharingPolynomialContext> resharingPolynomialContexts;
    private final Lock lock;

    public DistributedPolynomialManager(DistributedPolynomial distributedPolynomial,
                                        ResharingPolynomialListener resharingListener) {
        this.distributedPolynomial = distributedPolynomial;
        this.resharingListener = resharingListener;
        this.resharingPolynomialContexts = new ConcurrentHashMap<>();
        this.lock = new ReentrantLock(true);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RESHARING);
    }

    public void createResharingPolynomials(int oldF, int[] oldMembers, int newF, int[] newMembers, int nPolynomials) {
        lock.lock();
        PolynomialContext oldView = new PolynomialContext(
                oldF,
                BigInteger.ZERO,
                null,
                oldMembers
        );
        PolynomialContext newView = new PolynomialContext(
                newF,
                BigInteger.ZERO,
                null,
                newMembers
        );
        int internalId = internalSequenceNumber;
        logger.info("Starting creation of {} polynomial(s) with id {} for resharing", nPolynomials,
                internalId);
        for (int i = 0; i < nPolynomials; i++) {
            int id = internalSequenceNumber++;
            int leader = oldMembers[id % oldMembers.length];
            PolynomialCreationContext creationContext = new PolynomialCreationContext(
                    id,
                    internalId,
                    nPolynomials,
                    false,
                    false,
                    leader,
                    PolynomialCreationReason.RESHARING,
                    oldView,
                    newView
            );
            logger.debug("Starting creation of new polynomial with id {} for resharing", id);
            distributedPolynomial.createNewPolynomial(creationContext);
        }

        ResharingPolynomialContext context = new ResharingPolynomialContext(
                internalId,
                nPolynomials,
                oldF,
                newF,
                oldMembers,
                newMembers
        );

        if (!resharingPolynomialContexts.containsKey(internalId)) {
            context.startTime();
            resharingPolynomialContexts.put(internalId, context);
        } else
            logger.warn("There is already an active resharing polynomial creation with internal id {}", internalId);
        lock.unlock();
    }

    @Override
    public void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                            PolynomialPoint point) {
        lock.lock();
        logger.debug("Created new {} polynomial(s) with id {}", point.getShares().size(), context.getId());

        if (context.getReason() == PolynomialCreationReason.RESHARING) {
            ResharingPolynomialContext polynomialContext = resharingPolynomialContexts.get(context.getInternalId());
            if (polynomialContext == null) {
                logger.debug("There is no resharing polynomial context. Creating one");
                PolynomialContext oldContext = context.getContexts()[0];
                PolynomialContext newContext = context.getContexts()[1];
                polynomialContext = new ResharingPolynomialContext(
                        context.getInternalId(),
                        context.getNPolynomials(),
                        oldContext.getF(),
                        newContext.getF(),
                        oldContext.getMembers(),
                        newContext.getMembers()
                );
                resharingPolynomialContexts.put(context.getInternalId(), polynomialContext);
            }
            polynomialContext.addPolynomial(context.getId(), point);
            polynomialContext.setCID(consensusId);
            if (polynomialContext.currentIndex % 5000 == 0 && polynomialContext.currentIndex != polynomialContext.getNPolynomials())
                logger.info("{} polynomial(s) created", polynomialContext.currentIndex);

            if (polynomialContext.currentIndex == polynomialContext.getNPolynomials()) {
                polynomialContext.endTime();
                double delta = polynomialContext.getTime() / 1_000_000.0;
                logger.info("Took {} ms to create {} polynomial(s) for resharing", delta, polynomialContext.getNPolynomials());
                resharingListener.onResharingPolynomialsCreation(polynomialContext);
            }
        }
        lock.unlock();
    }

    @Override
    public synchronized void onPolynomialCreationFailure(PolynomialCreationContext context,
                                                         List<ProposalMessage> invalidProposals, int consensusId) {
        logger.error("I received an invalid point");
        System.exit(-1);
    }
}
