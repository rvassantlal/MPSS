package confidential.polynomial;

import vss.Utils;
import vss.commitment.Commitment;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.HashMap;
import java.util.Map;

public class Proposal implements Externalizable {
    private Map<Integer, byte[]> points;
    private Commitment[] commitments;

    public Proposal() { }

    public Proposal(Map<Integer, byte[]> points, Commitment... commitments) {
        this.points = points;
        this.commitments = commitments;
    }

    public Map<Integer, byte[]> getPoints() {
        return points;
    }

    public Commitment[] getCommitments() {
        return commitments;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(points == null ? -1 : points.size());
        for (Map.Entry<Integer, byte[]> entry : points.entrySet()) {
            out.writeInt(entry.getKey());
            byte[] b = entry.getValue();
            out.writeInt(b.length);
            out.write(b);

        }
        out.writeInt(commitments.length);
        for (Commitment commitment : commitments) {
            Utils.writeCommitment(commitment, out);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int size = in.readInt();
        if (size != -1) {
            points = new HashMap<>(size);
            byte[] b;
            while (size-- > 0) {
                int shareholder = in.readInt();
                b = new byte[in.readInt()];
                in.readFully(b);
                points.put(shareholder, b);
            }
        }
        commitments = new Commitment[in.readInt()];
        for (int i = 0; i < commitments.length; i++) {
            commitments[i] = Utils.readCommitment(in);
        }
    }
}
