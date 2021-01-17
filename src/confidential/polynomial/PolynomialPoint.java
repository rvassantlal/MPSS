package confidential.polynomial;

import vss.commitment.Commitment;
import vss.secretsharing.Share;

import java.util.Map;

public class PolynomialPoint {
    private final Map<Integer, Share> shares;
    private final Map<Integer, Commitment> commitments;

    public PolynomialPoint(Map<Integer, Share> shares, Map<Integer, Commitment> commitments) {
        this.shares = shares;
        this.commitments = commitments;
    }

    public Commitment getCommitments(int label) {
        return commitments.get(label);
    }

    public Share getShares(int label) {
        return shares.get(label);
    }

    @Override
    public String toString() {
        return "PolynomialPoint{" +
                "shares=" + shares +
                ", commitments=" + commitments +
                '}';
    }
}
