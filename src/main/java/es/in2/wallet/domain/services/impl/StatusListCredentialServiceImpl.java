package es.in2.wallet.domain.services.impl;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.domain.entities.StatusListCredentialData;
import es.in2.wallet.domain.exceptions.StatusListCredentialException;
import es.in2.wallet.domain.services.StatusListCredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

@Slf4j
@RequiredArgsConstructor
@Service
public class StatusListCredentialServiceImpl implements StatusListCredentialService {

    private final ObjectMapper objectMapper;

    /**
     * Ensures that the status purpose in the Status List Credential matches
     * the expected purpose from the subject credential.
     */
    @Override
    public void validateStatusPurposeMatches(String statusListCredentialPurpose, String expectedPurpose) {
        // Log at debug to avoid noisy logs on happy path
        log.debug("Validating statusPurpose match. expectedPurpose='{}', statusListCredentialPurpose='{}'",
                expectedPurpose, statusListCredentialPurpose);

        if (expectedPurpose == null || expectedPurpose.isBlank()) {
            log.warn("Expected statusPurpose is missing or blank");
            throw new StatusListCredentialException("Expected statusPurpose cannot be blank");
        }

        if (statusListCredentialPurpose == null || statusListCredentialPurpose.isBlank()) {
            log.warn("Status List Credential statusPurpose is missing or blank");
            throw new StatusListCredentialException("Status List Credential statusPurpose cannot be blank");
        }

        if (!statusListCredentialPurpose.equals(expectedPurpose)) {
            log.warn("StatusPurpose mismatch. expected='{}', actual='{}'",
                    expectedPurpose, statusListCredentialPurpose);
            throw new StatusListCredentialException(
                    "StatusPurpose mismatch. expected=" + expectedPurpose + ", actual=" + statusListCredentialPurpose
            );
        }

        log.debug("StatusPurpose match OK. purpose='{}'", expectedPurpose);
    }

    /**
     * Parses a Status List Credential JWT (application/vc+jwt) and extracts:
     * - issuer (may be null)
     * - credentialSubject.statusPurpose (required)
     * - credentialSubject.encodedList -> raw bitstring bytes
     */
    public StatusListCredentialData parse(String jwtString) {
        if (jwtString == null || jwtString.isBlank()) {
            throw new StatusListCredentialException("JWT string cannot be blank");
        }

        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtString);
        } catch (ParseException e) {
            throw new StatusListCredentialException("Invalid JWT format", e);
        }

        final String issuer;
        try {
            issuer = signedJWT.getJWTClaimsSet().getStringClaim("issuer");
        } catch (Exception e) {
            throw new StatusListCredentialException("Error reading 'issuer' claim", e);
        }

        final JsonNode claims = objectMapper.valueToTree(readClaimsSafely(signedJWT));

        final JsonNode credentialSubject = getRequiredObject(claims, "credentialSubject");

        final String statusPurpose = getRequiredText(credentialSubject, "statusPurpose");
        final String encodedList = getRequiredText(credentialSubject, "encodedList");

        final byte[] rawBytes = decodeEncodedListToRawBytes(encodedList);

        return new StatusListCredentialData(issuer, statusPurpose, rawBytes);
    }

    /**
     * Returns true if the bit at bitIndex is set (LSB-first within each byte).
     */
    public boolean isBitSet(byte[] rawBytes, int bitIndex) {
        if (rawBytes == null) {
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        if (bitIndex < 0) {
            throw new StatusListCredentialException("bitIndex must be >= 0");
        }

        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            throw new StatusListCredentialException(
                    "bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex
            );
        }

        int byteIndex = bitIndex / 8;
        int bitInByte = bitIndex % 8;
        int mask = 1 << bitInByte;

        return (rawBytes[byteIndex] & mask) != 0;
    }

    public int maxBits(byte[] rawBytes) {
        if (rawBytes == null) {
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        return rawBytes.length * 8;
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    private Object readClaimsSafely(SignedJWT signedJWT) {
        try {
            return signedJWT.getJWTClaimsSet().toJSONObject();
        } catch (ParseException e) {
            throw new StatusListCredentialException("Error reading JWT claims set", e);
        }
    }

    private JsonNode getRequiredObject(JsonNode parent, String field) {
        if (parent == null || parent.isNull()) {
            throw new StatusListCredentialException("Missing JWT claims");
        }
        JsonNode node = parent.get(field);
        if (node == null || node.isNull() || !node.isObject()) {
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node;
    }

    private String getRequiredText(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null || !node.isTextual() || node.asText().isBlank()) {
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node.asText();
    }

    private byte[] decodeEncodedListToRawBytes(String encodedList) {
        if (encodedList == null || encodedList.isBlank()) {
            throw new StatusListCredentialException("encodedList cannot be blank");
        }

        String payload = encodedList.trim();
        if (payload.charAt(0) != 'u') {
            throw new StatusListCredentialException(
                    "encodedList must start with multibase base64url prefix 'u'"
            );
        }

        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(payload.substring(1));
        } catch (IllegalArgumentException e) {
            throw new StatusListCredentialException("encodedList is not valid base64url", e);
        }

        return gunzip(gzipped);
    }

    private byte[] gunzip(byte[] input) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(input);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = gzip.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new StatusListCredentialException("Failed to gunzip content", e);
        }
    }
}
