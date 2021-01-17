package confidential.statemanagement;

import vss.secretsharing.Share;

import java.util.LinkedList;

public class BlindedApplicationState {
    private final byte[] commonState;
    private final byte[] commitments;
    private final LinkedList<Share> shares;


    public BlindedApplicationState(byte[] commonState, LinkedList<Share> shares,
                                   byte[] commitments) {
        this.commonState = commonState;
        this.shares = shares;
        this.commitments = commitments;
    }

    public byte[] getCommonState() {
        return commonState;
    }

    public LinkedList<Share> getShares() {
        return shares;
    }

    public byte[] getCommitments() {
        return commitments;
    }
}
