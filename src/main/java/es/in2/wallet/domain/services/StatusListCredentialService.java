package es.in2.wallet.domain.services;


import es.in2.wallet.domain.entities.StatusListCredentialData;
import es.in2.wallet.domain.exceptions.StatusListCredentialException;

/**
 * Service responsible for parsing and interpreting Status List Credentials
 * (application/vc+jwt) according to the Bitstring Status List specification.
 *
 * This service is stateless and shared between wallet and verifier.
 */
public interface StatusListCredentialService {

    /**
     * Ensures that the status purpose declared in the Status List Credential
     * matches the expected purpose declared in the subject credential.
     *
     * @param statusListCredentialPurpose   statusPurpose extracted from the Status List Credential
     * @param expectedPurpose statusPurpose declared in the subject credential
     * @throws StatusListCredentialException if the purposes do not match or are invalid
     */
    void validateStatusPurposeMatches(String statusListCredentialPurpose, String expectedPurpose);

    /**
     * Parses a Status List Credential JWT and extracts its semantic content.
     *
     * @param jwtString the Status List Credential in JWT (vc+jwt) format
     * @return parsed status list credential data
     * @throws StatusListCredentialException if the JWT is invalid or does not
     *         conform to the expected Status List Credential structure
     */
    StatusListCredentialData parse(String jwtString);

    /**
     * Returns whether the bit at the given index is set in the decoded bitstring.
     * Bit numbering is LSB-first within each byte.
     *
     * @param rawBytes decoded bitstring bytes
     * @param bitIndex zero-based bit index
     * @return true if the bit is set, false otherwise
     * @throws StatusListCredentialException if the index is invalid or out of range
     */
    boolean isBitSet(byte[] rawBytes, int bitIndex);

    /**
     * Returns the maximum number of bits available in the decoded bitstring.
     *
     * @param rawBytes decoded bitstring bytes
     * @return total number of bits
     * @throws StatusListCredentialException if rawBytes is null
     */
    int maxBits(byte[] rawBytes);
}