package confidential.statemanagement.utils;

import confidential.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.SocketFactory;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class PublicDataSender extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final String receiverServerIp;
    private final int receiverServerPort;
    private final int nDataToSend;
    private final int processId;
    private final BlockingQueue<byte[]> states;

    public PublicDataSender(String receiverServerIp, int receiverServerPort, int processId, int nDataToSend) {
        super("Common State Sender Thread");
        this.receiverServerIp = receiverServerIp;
        this.receiverServerPort = receiverServerPort;
        this.nDataToSend = nDataToSend;
        this.states = new LinkedBlockingQueue<>(nDataToSend);
        this.processId = processId;
    }

    public void sendData(byte[] data) {
        try {
            states.put(data);
        } catch (InterruptedException e) {
            logger.error("Failed to add data for sending", e);
        }
    }

    @Override
    public void run() {
        logger.debug("Connecting un-securely to {}:{}", receiverServerIp, receiverServerPort);
        try (Socket connection = SocketFactory.getDefault().createSocket(receiverServerIp, receiverServerPort);
             BufferedOutputStream out = new BufferedOutputStream(connection.getOutputStream())) {
            long t1, t2;
            out.write(Utils.toBytes(processId));

            long total = 0;
            for (int i = 0; i < nDataToSend; i++) {
                byte[] state = states.take();
                t1 = System.nanoTime();
                out.write(Utils.toBytes(state.length));
                out.write(state);
                t2 = System.nanoTime();
                total += t2 - t1;
            }
            t1 = System.nanoTime();
            out.flush();
            t2 = System.nanoTime();
            total += t2 - t1;
            logger.info("Took {} ms to send public data to {}:{}", total / 1_000_000.0,
                    receiverServerIp, receiverServerPort);
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to send public data to {}:{}.", receiverServerIp, receiverServerPort, e);
        }
    }
}
