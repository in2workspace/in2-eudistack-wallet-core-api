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

    @Override
    public void validateStatusPurposeMatches(String statusListCredentialPurpose, String expectedPurpose) {
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

    public StatusListCredentialData parse(String jwtString) {
        log.debug("Parsing StatusListCredential JWT (present={}, length={})",
                jwtString != null, jwtString == null ? 0 : jwtString.length());

        if (jwtString == null || jwtString.isBlank()) {
            log.warn("JWT string is null/blank");
            throw new StatusListCredentialException("JWT string cannot be blank");
        }

        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtString);
            log.debug("JWT parsed successfully");
        } catch (ParseException e) {
            log.warn("Invalid JWT format", e);
            throw new StatusListCredentialException("Invalid JWT format", e);
        }

        final String issuer;
        try {
            issuer = signedJWT.getJWTClaimsSet().getStringClaim("issuer");
            log.debug("Issuer claim read successfully (present={})", issuer != null && !issuer.isBlank());
        } catch (Exception e) {
            log.warn("Error reading 'issuer' claim", e);
            throw new StatusListCredentialException("Error reading 'issuer' claim", e);
        }

        final JsonNode claims = objectMapper.valueToTree(readClaimsSafely(signedJWT));
        log.debug("JWT claims converted to JsonNode (isNull={})", claims == null || claims.isNull());

        final JsonNode credentialSubject = getRequiredObject(claims, "credentialSubject");
        log.debug("credentialSubject extracted");

        final String statusPurpose = getRequiredText(credentialSubject, "statusPurpose");
        log.debug("statusPurpose extracted='{}'", statusPurpose);

        final String encodedList = getRequiredText(credentialSubject, "encodedList");
        log.debug("encodedList extracted (length={})", encodedList.length());

        final byte[] rawBytes = decodeEncodedListToRawBytes(encodedList);
        log.debug("encodedList decoded and gunzipped (rawBytesLength={}, maxBits={})",
                rawBytes.length, maxBits(rawBytes));

        return new StatusListCredentialData(issuer, statusPurpose, rawBytes);
    }

    public boolean isBitSet(byte[] rawBytes, int bitIndex) {
        log.debug("Checking bit (bitIndex={}, rawBytesLength={})",
                bitIndex, rawBytes == null ? null : rawBytes.length);

        if (rawBytes == null) {
            log.warn("rawBytes is null");
            throw new StatusListCredentialException("rawBytes cannot be null");
        }

        if (bitIndex < 0) {
            log.warn("bitIndex is negative (bitIndex={})", bitIndex);
            throw new StatusListCredentialException("bitIndex must be >= 0");
        }

        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            log.warn("bitIndex out of range (bitIndex={}, maxBits={})", bitIndex, maxBits);
            throw new StatusListCredentialException(
                    "bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex
            );
        }

        int byteIndex = bitIndex / 8;
        int bitInByte = 7 - (bitIndex % 8);
        int mask = 1 << bitInByte;

        boolean result = (rawBytes[byteIndex] & mask) != 0;
        log.debug("Bit check computed (byteIndex={}, bitInByte={}, mask=0x{}, isSet={})",
                byteIndex, bitInByte, Integer.toHexString(mask), result);

        return result;
    }

    public int maxBits(byte[] rawBytes) {
        if (rawBytes == null) {
            log.warn("rawBytes is null when calculating maxBits");
            throw new StatusListCredentialException("rawBytes cannot be null");
        }
        int result = rawBytes.length * 8;
        log.debug("maxBits computed (rawBytesLength={}, maxBits={})", rawBytes.length, result);
        return result;
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    private Object readClaimsSafely(SignedJWT signedJWT) {
        try {
            return signedJWT.getJWTClaimsSet().toJSONObject();
        } catch (ParseException e) {
            log.warn("Error reading JWT claims set", e);
            throw new StatusListCredentialException("Error reading JWT claims set", e);
        }
    }

    private JsonNode getRequiredObject(JsonNode parent, String field) {
        if (parent == null || parent.isNull()) {
            log.warn("Missing JWT claims (parent is null)");
            throw new StatusListCredentialException("Missing JWT claims");
        }
        JsonNode node = parent.get(field);
        if (node == null || node.isNull() || !node.isObject()) {
            log.warn("Missing or invalid object field '{}' (present={}, isNull={}, isObject={})",
                    field, node != null, node == null || node.isNull(), node != null && node.isObject());
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node;
    }

    private String getRequiredText(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null || !node.isTextual() || node.asText().isBlank()) {
            log.warn("Missing or invalid text field '{}'", field);
            throw new StatusListCredentialException("Missing or invalid '" + field + "'");
        }
        return node.asText();
    }

    private byte[] decodeEncodedListToRawBytes(String encodedList) {
        if (encodedList == null || encodedList.isBlank()) {
            log.warn("encodedList is null/blank");
            throw new StatusListCredentialException("encodedList cannot be blank");
        }

        String payload = encodedList.trim();
        if (payload.charAt(0) != 'u') {
            log.warn("encodedList missing multibase prefix 'u' (firstChar='{}')", payload.charAt(0));
            throw new StatusListCredentialException(
                    "encodedList must start with multibase base64url prefix 'u'"
            );
        }

        final byte[] gzipped;
        try {
            gzipped = Base64.getUrlDecoder().decode(payload.substring(1));
        } catch (IllegalArgumentException e) {
            log.warn("encodedList is not valid base64url", e);
            throw new StatusListCredentialException("encodedList is not valid base64url", e);
        }

        return gunzip(gzipped);
    }

    private byte[] gunzip(byte[] input) {
        log.debug("Gunzipping content (inputLength={})", input == null ? null : input.length);
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
