package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class ProposalMessage extends PolynomialMessage {
    private Proposal proposal;
    private byte[] cryptographicHash;
    private byte[] signature;

    public ProposalMessage() {}

    public ProposalMessage(int id, int sender, Proposal proposal) {
        super(id, sender);
        this.proposal = proposal;
    }

    public Proposal getProposal() {
        return proposal;
    }

    public byte[] getCryptographicHash() {
        return cryptographicHash;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setCryptographicHash(byte[] cryptographicHash) {
        this.cryptographicHash = cryptographicHash;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        proposal.writeExternal(out);

        out.writeInt(signature == null ? -1 : signature.length);
        if (signature != null)
            out.write(signature);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        proposal = new Proposal();
        proposal.readExternal(in);

        int size = in.readInt();
        if (size > -1) {
            signature = new byte[size];
            in.readFully(signature);
        }
    }
}
