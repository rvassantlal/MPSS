package confidential.polynomial.messages;

import confidential.polynomial.PolynomialMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Objects;

public class MPSSProposalResponse extends PolynomialMessage {
    private long view;
    private byte[][][] invalidProposals;

    public MPSSProposalResponse() { }

    public MPSSProposalResponse(int id, int sender, long view, byte[][][] invalidProposals) {
        super(id, sender);
        this.view = view;
        this.invalidProposals = invalidProposals;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MPSSProposalResponse that = (MPSSProposalResponse) o;
        return view == that.view && Arrays.equals(invalidProposals, that.invalidProposals);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(view);
        result = 31 * result + Arrays.hashCode(invalidProposals);
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
