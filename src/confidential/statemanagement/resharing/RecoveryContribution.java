package confidential.statemanagement.resharing;

import vss.commitment.Commitment;
import vss.secretsharing.VerifiableShare;

public class RecoveryContribution {
    private final VerifiableShare[] shares;
    private final Commitment[] rCommitments;

    public RecoveryContribution(VerifiableShare[] shares, Commitment[] rCommitments) {
        this.shares = shares;
        this.rCommitments = rCommitments;
    }

    public VerifiableShare[] getShares() {
        return shares;
    }

    public Commitment[] getRCommitments() {
        return rCommitments;
    }
}
