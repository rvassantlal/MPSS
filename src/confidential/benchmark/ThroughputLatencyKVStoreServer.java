package confidential.benchmark;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.demo.map.Operation;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class ThroughputLatencyKVStoreServer implements ConfidentialSingleExecutable {
    private Logger logger = LoggerFactory.getLogger("demo");
    private Map<String, ConfidentialData> map;
    private long startTime;
    private long numRequests;
    private Set<Integer> senders;
    private double maxThroughput;

    public static void main(String[] args) throws NumberFormatException {
        new ThroughputLatencyKVStoreServer(Integer.parseInt(args[0]));
    }

    ThroughputLatencyKVStoreServer(int processId) {
        map = new TreeMap<>();
        senders = new HashSet<>(1000);
        new ConfidentialServerFacade(processId, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        numRequests++;
        senders.add(msgCtx.getSender());

        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            ConfidentialData value;
            switch (op) {
                case GET:
                    str = in.readUTF();
                    value = map.get(str);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case PUT:
                    str = in.readUTF();
                    map.put(str, shares[0]);

                    return new ConfidentialMessage();
                case REMOVE:
                    str = in.readUTF();
                    value = map.remove(str);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case GET_ALL:
                    if (map.isEmpty())
                        return new ConfidentialMessage();
                    ConfidentialData[] allValues = new ConfidentialData[map.size()];
                    int i = 0;
                    for (ConfidentialData share : map.values())
                        allValues[i++] = share;
                    return new ConfidentialMessage(null, allValues);
            }
        } catch (IOException e) {
            logger.error("Failed to attend ordered request from {}", msgCtx.getSender(), e);
        } finally {
            printMeasurement();
        }
        return null;
    }

    private void printMeasurement() {
        long currentTime = System.nanoTime();
        double deltaTime = (currentTime - startTime) / 1_000_000_000.0;
        if ((int) (deltaTime / 2) > 0) {
            long delta = currentTime - startTime;
            double throughput = numRequests / deltaTime;
            if (throughput > maxThroughput)
                maxThroughput = throughput;
            logger.info("M:(clients[#]|requests[#]|delta[ns]|throughput[ops/s], max[ops/s])>({}|{}|{}|{}|{})",
                    senders.size(), numRequests, delta, throughput, maxThroughput);
            //logger.info("Clients: {} | Requests: {} | DeltaTime[s]: {} | Throughput[ops/s]: {} (max: {})",
            //        senders.size(), numRequests, deltaTime, throughput, maxThroughput);
            numRequests = 0;
            startTime = currentTime;
            senders.clear();
        }
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        numRequests++;
        senders.add(msgCtx.getSender());

        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            ConfidentialData value;
            switch (op) {
                case GET:
                    str = in.readUTF();
                    value = map.get(str);

                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case GET_ALL:
                    if (map.isEmpty())
                        return new ConfidentialMessage();
                    ConfidentialData[] allValues = (ConfidentialData[]) map.values().toArray();
                    return new ConfidentialMessage(null, allValues);
            }
        } catch (IOException e) {
            logger.error("Failed to attend unordered request from {}", msgCtx.getSender(), e);
        } finally {
            printMeasurement();
        }
        return null;
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeInt(map.size());
            ConfidentialData[] shares = new ConfidentialData[map.size()];
            int i = 0;
            for (Map.Entry<String, ConfidentialData> e : map.entrySet()) {
                out.writeUTF(e.getKey());
                shares[i++] = e.getValue();
            }
            out.flush();
            bos.flush();
            return new ConfidentialSnapshot(bos.toByteArray(), shares);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
             ObjectInput in = new ObjectInputStream(bis)) {
            int size = in.readInt();
            map = new TreeMap<>();
            ConfidentialData[] shares = snapshot.getShares();
            for (int i = 0; i < size; i++) {
                map.put(in.readUTF(), shares[i]);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
