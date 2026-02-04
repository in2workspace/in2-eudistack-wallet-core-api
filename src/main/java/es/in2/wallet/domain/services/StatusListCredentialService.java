package es.in2.wallet.domain.services;


import es.in2.wallet.domain.entities.StatusListCredentialData;

public interface StatusListCredentialService {

    /**
     * Ensures that the status purpose declared in the Status List Credential
     * matches the expected purpose declared in the subject credential.
     */
    void validateStatusPurposeMatches(String statusListCredentialPurpose, String expectedPurpose);

    /**
     * Parses a Status List Credential JWT and extracts its semantic content.
     */
    StatusListCredentialData parse(String jwtString);

    /**
     * Returns whether the bit at the given index is set in the decoded bitstring.
     */
    boolean isBitSet(byte[] rawBytes, int bitIndex);

    /**
     * Returns the maximum number of bits available in the decoded bitstring.
     */
    int maxBits(byte[] rawBytes);
}