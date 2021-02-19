package confidential.interServersCommunication;

import bftsmart.tom.MessageContext;

public class InterServerMessageHolder {
    private final byte[] serializedMessage;
    private final MessageContext messageContext;

    public InterServerMessageHolder(byte[] serializedMessage, MessageContext messageContext) {
        this.serializedMessage = serializedMessage;
        this.messageContext = messageContext;
    }

    public byte[] getSerializedMessage() {
        return serializedMessage;
    }

    public MessageContext getMessageContext() {
        return messageContext;
    }
}
