package confidential.interServersCommunication;

import bftsmart.communication.ServerCommunicationSystem;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.ForwardedMessage;
import bftsmart.tom.core.messages.TOMMessage;
import confidential.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

public class InterServersCommunication {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private final TOMMessageGenerator tomMessageGenerator;
    private final ServerCommunicationSystem communicationSystem;
    private final Map<InterServersMessageType, InterServerMessageListener> listeners;
    private final CommunicationManager communicationManager;
    private final int pid;
    private InterServerMessageListener listener;

    public InterServersCommunication(ServerCommunicationSystem communicationSystem, ServerViewController viewController) {
        this.tomMessageGenerator = new TOMMessageGenerator(viewController);
        this.communicationSystem = communicationSystem;
        this.listeners = new HashMap<>();
        this.communicationManager = new CommunicationManager(viewController);
        this.communicationManager.start();
        this.pid = viewController.getStaticConf().getProcessId();
    }

    public synchronized void sendOrdered(byte[] metadata, byte[] request,
                            int... targets) {
        TOMMessage msg = tomMessageGenerator.getNextOrdered(metadata, serializeRequest(request));
        communicationSystem.send(targets, new ForwardedMessage(msg.getSender(), msg));
    }

    public boolean registerListener(MessageListener listener) {
        return communicationManager.registerMessageListener(listener);
    }

    public synchronized void sendUnordered(CommunicationTag tag, byte[] request, int... targets) {
        communicationManager.send(tag, new InternalMessage(pid, tag, request), targets);
    }

    public void registerListener(InterServerMessageListener listener, InterServersMessageType messageType,
                                 InterServersMessageType... moreMessageTypes) {
        if (listener == null)
            logger.error("Inter server message listener is null");
        this.listener = listener;
    }

    public void messageReceived(byte[] message, MessageContext msgCtx) {
        listener.messageReceived(new InterServerMessageHolder(message, msgCtx));
    }

    private byte[] serializeRequest(byte[] request) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) MessageType.APPLICATION.ordinal());
            out.writeInt(request.length);
            out.write(request);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
