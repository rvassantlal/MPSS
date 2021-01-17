package confidential.polynomial.messages;

import confidential.polynomial.PolynomialMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Objects;

public class MPSSProposalSet extends PolynomialMessage {
    private long view;
    private int[][] receivedNodes;
    private byte[][][] receivedProposals;

    public MPSSProposalSet() { }

    public MPSSProposalSet(int id, int sender, long view, int[][] receivedNodes, byte[][][] receivedProposals) {
        super(id, sender);
        this.view = view;
        this.receivedNodes = receivedNodes;
        this.receivedProposals = receivedProposals;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MPSSProposalSet that = (MPSSProposalSet) o;
        return view == that.view && Arrays.equals(receivedNodes, that.receivedNodes) && Arrays.equals(receivedProposals, that.receivedProposals);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(view);
        result = 31 * result + Arrays.hashCode(receivedNodes);
        result = 31 * result + Arrays.hashCode(receivedProposals);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
    }
}
