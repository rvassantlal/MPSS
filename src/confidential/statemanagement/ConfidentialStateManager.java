package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.core.DeliveryThread;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.Configuration;
import confidential.Utils;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.privatestate.sender.StateSeparationListener;
import confidential.statemanagement.resharing.ResharingBlindedStateHandler;
import confidential.statemanagement.resharing.ResharingBlindedStateSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements ReconstructionCompleted,
        ResharingPolynomialListener {
    private final long RENEWAL_PERIOD;
    private final int SERVER_STATE_LISTENING_PORT;
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final static long INIT_TIMEOUT = 60 * 60 * 1000;
    private DistributedPolynomialManager distributedPolynomialManager;
    private ServerConfidentialityScheme confidentialityScheme;
    private Timer stateTimer;
    private long timeout = INIT_TIMEOUT;
    private final ReentrantLock lockTimer;
    private final AtomicInteger sequenceNumber;
    private final HashMap<Integer, Integer> sequenceNumbers;
    private final Timer refreshTimer;
    private long recoveryStartTime;
    private long renewalStartTime;
    private final Set<Integer> usedReplicas;
    private boolean isRefreshing;
    private ResharingBlindedStateSender resharingStateSender;
    private TimerTask refreshTriggerTask;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        sequenceNumber = new AtomicInteger();
        sequenceNumbers = new HashMap<>();
        refreshTimer = new Timer("Refresh Timer");
        usedReplicas = new HashSet<>();
        RENEWAL_PERIOD = Configuration.getInstance().getRenewalPeriod();
        SERVER_STATE_LISTENING_PORT = Configuration.getInstance().getRecoveryPort();
    }

    public void setDistributedPolynomial(DistributedPolynomial distributedPolynomial) {
        this.distributedPolynomialManager = new DistributedPolynomialManager(distributedPolynomial, this);
        if (Configuration.getInstance().isRenewalActive()) {
            setRefreshTimer();
            logger.info("Renewal is active ({} s period)", RENEWAL_PERIOD / 1000);
        } else
            logger.info("Renewal is deactivated");
    }

    public void setConfidentialityScheme(ServerConfidentialityScheme confidentialityScheme) {
        this.confidentialityScheme = confidentialityScheme;
    }

    @Override
    public void init(TOMLayer tomLayer, DeliveryThread dt) {
        super.init(tomLayer, dt);
        tomLayer.requestsTimer.Enabled(false);
    }

    private int getRandomReplica() {
        int[] processes = SVController.getCurrentViewOtherAcceptors();
        Random rnd = new Random();
        while (true) {
            int i = rnd.nextInt(processes.length);
            int replica = processes[i];
            if (!usedReplicas.contains(replica)) {
                usedReplicas.add(replica);
                return replica;
            }
        }
    }

    @Override
    protected void requestState() {
        logger.debug("requestState");
        recoveryStartTime = System.nanoTime();

        if (tomLayer.requestsTimer != null)
            tomLayer.requestsTimer.clearAll();

        int stateSenderReplica = getRandomReplica();

        DefaultSMMessage recoverySMMessage = new DefaultSMMessage(
                SVController.getStaticConf().getProcessId(),
                waitingCID,
                TOMUtil.SM_REQUEST,
                null,
                SVController.getCurrentView(),
                -1,
                tomLayer.execManager.getCurrentLeader(),
                stateSenderReplica,
                SERVER_STATE_LISTENING_PORT
        );

        logger.info("Replica {} will send full state", stateSenderReplica);
        logger.info("Sending request for state up to CID {} to {}", waitingCID,
                Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), recoverySMMessage);

        tomLayer.requestsTimer.Enabled(false);

        TimerTask stateTask = new TimerTask() {
            @Override
            public void run() {
                logger.info("Timeout to retrieve state");
                SMMessage message = new DefaultSMMessage(
                        SVController.getStaticConf().getProcessId(),
                        waitingCID,
                        TOMUtil.TRIGGER_SM_LOCALLY,
                        null,
                        null,
                        -1,
                        -1,
                        -1,
                        -1
                );
                triggerTimeout(message);
            }
        };

        stateTimer = new Timer("State Timer");
        timeout *= 2;
        stateTimer.schedule(stateTask, timeout);
    }

    @Override
    public void stateTimeout() {
        lockTimer.lock();
        logger.debug("Timeout for the replicas that were supposed to send the state. Trying again");
        if (stateTimer != null) {
            stateTimer.cancel();
        }
        reset();
        requestState();
        lockTimer.unlock();
    }

    @Override
    public void SMRequestDeliver(SMMessage msg, boolean isBFT) {
        if (msg instanceof DefaultSMMessage) {
            logger.debug("Received recovery request from {}", msg.getSender());
            throw new UnsupportedOperationException("Use resharing");
        } else
            logger.warn("Received unknown SM message type from {}", msg.getSender());
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            RecoveryStateServerSMMessage recoverySMMessage = (RecoveryStateServerSMMessage)msg;

            sequenceNumbers.merge(recoverySMMessage.getSequenceNumber(), 1, Integer::sum);
            if (!SVController.getStaticConf().isStateTransferEnabled())
                return;

            if (waitingCID == -1 || msg.getCID() != waitingCID) {
                logger.debug("I am not waiting for state or state contains different cid. WaitingCID: {} RequestCID: {}",
                        waitingCID, msg.getCID());
                return;
            }
            if (!appStateOnly) {
                senderRegencies.put(msg.getSender(), msg.getRegency());
                senderLeaders.put(msg.getSender(), msg.getLeader());
                senderViews.put(msg.getSender(), msg.getView());
            }
        } finally {
            lockTimer.unlock();
        }
    }

    /**
     * This method will be called after state is reconstructed, which means that this server already
     * have received f + 1 correct recovery states
     * @param recoveredState Recovered State
     */
    @Override
    public void onReconstructionCompleted(DefaultApplicationState recoveredState) {
        if (isRefreshing) {
            finishRefresh(recoveredState);
            return;
        }
        try {
            lockTimer.lock();

            int currentRegency;
            int currentLeader;
            View currentView;

            if (!appStateOnly) {
                Integer temp = getCurrentValue(senderRegencies);
                currentRegency = temp == null ? -1 : temp;
                temp = getCurrentValue(senderLeaders);
                currentLeader = temp == null ? -1 : temp;
                currentView = getCurrentValue(senderViews);
            } else {
                currentLeader = tomLayer.execManager.getCurrentLeader();
                currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
                currentView = SVController.getCurrentView();
            }

            if (currentRegency == -1 || currentLeader == -1 || currentView == null) {
                if (SVController.getCurrentViewN() - SVController.getCurrentViewF() <= getReplies()) {
                    logger.info("currentRegency or currentLeader or currentView are -1 or null");
                    if (stateTimer != null)
                        stateTimer.cancel();
                    reset();
                    requestState();
                } else {
                    logger.info("Waiting for more than {} states", SVController.getQuorum());
                }
                return;
            }

            logger.info("More than f states confirmed");

            if (stateTimer != null)
                stateTimer.cancel();

            tomLayer.getSynchronizer().getLCManager().setLastReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNextReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNewLeader(currentLeader);
            tomLayer.execManager.setNewLeader(currentLeader);

            logger.info("currentRegency: {} currentLeader: {} currentViewId: {}", currentRegency,
                    currentLeader, currentView.getId());

            // I might have timed out before invoking the state transfer, so
            // stop my re-transmission of STOP messages for all regencies up to the current one
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }

            logger.info("Restoring state");
            int seqNumber = getCorrectValue(sequenceNumbers);
            if (seqNumber == -1) {
                logger.error("Sequence numbers are different");
                reset();
                requestState();
                return;
            }

            sequenceNumber.set(seqNumber);

            state = recoveredState;

            if (state == null) {
                logger.error("Failed to reconstruct state. Retrying");
                reset();
                requestState();
                return;
            }
            logger.info("State reconstructed");

            dt.deliverLock();


            logger.info("Updating state");
            dt.update(state);

            logger.info("Last exec: {}", tomLayer.getLastExec());

            if (!appStateOnly && execManager.stopped()) {
                Queue<ConsensusMessage> stoppedMsgs = execManager.getStoppedMsgs();
                for (ConsensusMessage stopped : stoppedMsgs) {
                    if (stopped.getNumber() > state.getLastCID() /*msg.getCID()*/) {
                        execManager.addOutOfContextMessage(stopped);
                    }
                }
                logger.debug("Clear Stopped");
                execManager.clearStopped();
                execManager.restart();
            }

            logger.debug("Processing out of context messages");
            tomLayer.processOutOfContext();
            logger.debug("Finished processing out of context messages");

            if (SVController.getCurrentViewId() != currentView.getId()) {
                logger.info("Installing current view!");
                SVController.reconfigureTo(currentView);
            }

            isInitializing = false;

            waitingCID = -1;

            dt.canDeliver();
            dt.deliverUnlock();

            reset();

            logger.info("I updated the state!");
            tomLayer.requestsTimer.clearAll();
            tomLayer.requestsTimer.Enabled(true);


            if (appStateOnly) {
                appStateOnly = false;
                tomLayer.getSynchronizer().resumeLC();
            }
        } finally {
            lockTimer.unlock();
            long recoveryEndTime = System.nanoTime();
            double totalTime = (recoveryEndTime - recoveryStartTime) / 1_000_000.0;
            logger.info("Recovery duration: {} ms", totalTime);
        }
    }

    @Override
    public void onResharingPolynomialsCreation(ResharingPolynomialContext context) {
        logger.info("Received {} polynomials for resharing", context.getNPolynomials());

        refreshTriggerTask.cancel();
        int lastCID = context.getLastCID();
        isRefreshing = true;
        int[] oldMembers = context.getOldMembers();
        int[] newMembers = context.getNewMembers();
        int processId = SVController.getStaticConf().getProcessId();
        int leader = oldMembers[lastCID % oldMembers.length];
        if (Utils.isIn(processId, newMembers)) {
            int f = SVController.getCurrentViewF();
            int quorum = SVController.getCurrentViewN() - f;
            ResharingBlindedStateHandler blindedStateHandler = new ResharingBlindedStateHandler(
                    SVController,
                    SERVER_STATE_LISTENING_PORT,
                    f,
                    quorum,
                    leader,
                    confidentialityScheme,
                    this
            );
            blindedStateHandler.start();
        }

        if (Utils.isIn(processId, oldMembers)) {
            sendingBlindedState(context, leader, context.getPoints(), lastCID);
        }
    }

    private void sendingBlindedState(ResharingPolynomialContext creationContext, int leader,
                                     PolynomialPoint[] blindingShare, int consensusId) {
        try {
            dt.pauseDecisionDelivery();

            logger.info("Getting state");
            DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(consensusId, true);
            if (appState == null) {
                logger.error("Something went wrong while retrieving state up to {}", consensusId);
                return;
            }

            int[] receivers = creationContext.getNewMembers();
            boolean iAmStateSender = leader == SVController.getStaticConf().getProcessId();

            StateSeparationListener listener = nShares -> {};
            resharingStateSender = new ResharingBlindedStateSender(
                    SVController,
                    appState,
                    SERVER_STATE_LISTENING_PORT,
                    confidentialityScheme,
                    iAmStateSender,
                    listener,
                    receivers
            );
            resharingStateSender.setBlindingShares(blindingShare);
            resharingStateSender.start();
        } catch (Exception e) {
            logger.error("Failed to send blinded state.", e);
        }
    }

    protected void finishRefresh(DefaultApplicationState renewedState) {
        logger.info("Updating state");
        dt.refreshState(renewedState);
        logger.debug("State renewed");

        long endTime = System.nanoTime();
        double totalTime = (endTime - renewalStartTime) / 1_000_000.0;
        logger.info("Total renewal time: {}", totalTime);
        dt.resumeDecisionDelivery();
        isRefreshing = false;
        resharingStateSender = null;
        setRefreshTimer();
    }

    private void setRefreshTimer() {
        refreshTriggerTask = new TimerTask() {
            @Override
            public void run() {
                renewalStartTime = System.nanoTime();
                int nPolynomials = Configuration.getInstance().getNPolynomials();
                distributedPolynomialManager.createResharingPolynomials(
                        SVController.getCurrentViewF(),
                        SVController.getCurrentViewAcceptors(),
                        SVController.getCurrentViewF(),
                        SVController.getCurrentViewAcceptors(),
                        nPolynomials
                );
            }
        };

        refreshTimer.schedule(refreshTriggerTask, RENEWAL_PERIOD);
    }

    private int getCorrectValue(HashMap<Integer, Integer> senders) {
        int max = 0;
        int result = 0;
        for (Map.Entry<Integer, Integer> entry : senders.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = entry.getKey();
            }
        }
        if (max <= SVController.getCurrentViewF())
            return -1;
        return result;
    }

    private<T> T getCurrentValue(HashMap<Integer, T> senderValues) {
        Map<T, Integer> counter = new HashMap<>();
        for (T value : senderValues.values()) {
            counter.merge(value, 1, Integer::sum);
        }

        int max = 0;
        T result = null;
        for (Map.Entry<T, Integer> entry : counter.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = entry.getKey();
            }
        }
        if (max <= SVController.getCurrentViewF())
            return null;
        return result;
    }
}
