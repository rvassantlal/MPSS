package confidential.polynomial;

import java.util.List;

public interface PolynomialCreationListener {
    void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                     PolynomialPoint point);
    void onPolynomialCreationFailure(PolynomialCreationContext context,
                                     List<ProposalMessage> invalidProposals,
                                     int consensusId);
}