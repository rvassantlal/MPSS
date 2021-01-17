package confidential.polynomial.messages;

import confidential.polynomial.PolynomialMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Objects;

public class MPSSMissingProposal extends PolynomialMessage {
    private int index;
    private byte[] missingProposalHash;

    public MPSSMissingProposal() { }

    public MPSSMissingProposal(int id, int sender, int index, byte[] missingProposalHash) {
        super(id, sender);
        this.index = index;
        this.missingProposalHash = missingProposalHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MPSSMissingProposal that = (MPSSMissingProposal) o;
        return index == that.index && Arrays.equals(missingProposalHash, that.missingProposalHash);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(index);
        result = 31 * result + Arrays.hashCode(missingProposalHash);
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
