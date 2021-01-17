package confidential.statemanagement.utils;

public interface PublicStateListener {
    void deliverPublicState(int from, byte[] serializedBlindedShares,
                            byte[] serializedCommitments, byte[] commitmentsHash,
                            byte[] serializedCommonState, byte[] commonStateHash);
}
