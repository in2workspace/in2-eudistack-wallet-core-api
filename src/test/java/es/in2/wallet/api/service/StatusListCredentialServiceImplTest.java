package es.in2.wallet.api.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.domain.entities.StatusListCredentialData;
import es.in2.wallet.domain.exceptions.StatusListCredentialException;
import es.in2.wallet.domain.services.impl.StatusListCredentialServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class StatusListCredentialServiceImplTest {

    private StatusListCredentialServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StatusListCredentialServiceImpl(new ObjectMapper());
    }

    // -------------------------------------------------------------------------
    // validateStatusPurposeMatches
    // -------------------------------------------------------------------------

    @Test
    void validateStatusPurposeMatches_throwsWhenExpectedBlank() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches("revocation", "  ")
        );
        assertEquals("Expected statusPurpose cannot be blank", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_throwsWhenStatusListPurposeBlank() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches("  ", "revocation")
        );
        assertEquals("Status List Credential statusPurpose cannot be blank", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_throwsOnMismatch() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.validateStatusPurposeMatches("suspension", "revocation")
        );
        assertEquals("StatusPurpose mismatch. expected=revocation, actual=suspension", ex.getMessage());
    }

    @Test
    void validateStatusPurposeMatches_okWhenMatches() {
        assertDoesNotThrow(() -> service.validateStatusPurposeMatches("revocation", "revocation"));
    }

    // -------------------------------------------------------------------------
    // parse
    // -------------------------------------------------------------------------

    @Test
    void parse_throwsWhenJwtBlank() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse("   ")
        );
        assertEquals("JWT string cannot be blank", ex.getMessage());
    }

    @Test
    void parse_throwsWhenJwtInvalidFormat() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse("not-a-jwt")
        );
        assertEquals("Invalid JWT format", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parse_throwsWhenIssuerClaimIsNotString() throws Exception {
        String encodedList = multibaseBase64UrlGzipped(new byte[]{0x01});
        String jwt = buildSignedJwtWithIssuerClaim(123, "revocation", encodedList);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Error reading 'issuer' claim", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parse_throwsWhenCredentialSubjectMissing() throws Exception {
        String jwt = buildSignedJwtWithoutCredentialSubject("did:example:issuer");

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'credentialSubject'", ex.getMessage());
    }

    @Test
    void parse_throwsWhenStatusPurposeMissing() throws Exception {
        String jwt = buildSignedJwtMissingCredentialSubjectField("did:example:issuer", "statusPurpose");

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'statusPurpose'", ex.getMessage());
    }

    @Test
    void parse_throwsWhenEncodedListMissing() throws Exception {
        String jwt = buildSignedJwtMissingCredentialSubjectField("did:example:issuer", "encodedList");

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Missing or invalid 'encodedList'", ex.getMessage());
    }

    @Test
    void parse_throwsWhenEncodedListMissingMultibasePrefixU() throws Exception {
        byte[] raw = new byte[]{0x01, 0x02};
        String badEncodedList = "x" + Base64.getUrlEncoder().withoutPadding().encodeToString(gzip(raw));
        String jwt = buildSignedJwt("did:example:issuer", "revocation", badEncodedList);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("encodedList must start with multibase base64url prefix 'u'", ex.getMessage());
    }

    @Test
    void parse_throwsWhenEncodedListNotBase64Url() throws Exception {
        String badEncodedList = "u%%%";
        String jwt = buildSignedJwt("did:example:issuer", "revocation", badEncodedList);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("encodedList is not valid base64url", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parse_throwsWhenGunzipFails() throws Exception {
        // Valid base64url, but not gzipped content
        byte[] notGzipped = "hello".getBytes();
        String encodedList = "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(notGzipped);
        String jwt = buildSignedJwt("did:example:issuer", "revocation", encodedList);

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.parse(jwt)
        );
        assertEquals("Failed to gunzip content", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void parse_okHappyPath() throws Exception {
        byte[] raw = new byte[]{0x55, (byte) 0xAA, 0x00, 0x7F};
        String encodedList = multibaseBase64UrlGzipped(raw);
        String jwt = buildSignedJwt("did:example:issuer", "revocation", encodedList);

        StatusListCredentialData data = service.parse(jwt);

        assertEquals("did:example:issuer", data.issuer());
        assertEquals("revocation", data.statusPurpose());
        assertArrayEquals(raw, data.rawBitstringBytes());
    }

    // -------------------------------------------------------------------------
    // isBitSet & maxBits
    // -------------------------------------------------------------------------

    @Test
    void isBitSet_throwsWhenRawBytesNull() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(null, 0)
        );
        assertEquals("rawBytes cannot be null", ex.getMessage());
    }

    @Test
    void isBitSet_throwsWhenBitIndexNegative() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(new byte[]{0x00}, -1)
        );
        assertEquals("bitIndex must be >= 0", ex.getMessage());
    }

    @Test
    void isBitSet_throwsWhenOutOfRange() {
        byte[] raw = new byte[]{0x00}; // 8 bits
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.isBitSet(raw, 8)
        );
        assertEquals("bitIndex out of range. maxBits=8, bitIndex=8", ex.getMessage());
    }

    @Test
    void isBitSet_returnsCorrectValue_msbFirstWithinByteUsingImplementation() {
        byte[] raw = new byte[]{(byte) 0b1000_0000};

        assertTrue(service.isBitSet(raw, 0));  // checks MSB with this implementation
        assertFalse(service.isBitSet(raw, 1));
        assertFalse(service.isBitSet(raw, 7));
    }

    @Test
    void maxBits_throwsWhenRawBytesNull() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> service.maxBits(null)
        );
        assertEquals("rawBytes cannot be null", ex.getMessage());
    }

    @Test
    void maxBits_ok() {
        assertEquals(16, service.maxBits(new byte[]{0x00, 0x00}));
    }

    // -------------------------------------------------------------------------
    // Private helpers coverage via reflection
    // -------------------------------------------------------------------------

    @Test
    void getRequiredObject_throwsWhenParentNull() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> invokePrivate(service, "getRequiredObject",
                        new Class<?>[]{com.fasterxml.jackson.databind.JsonNode.class, String.class},
                        new Object[]{null, "credentialSubject"})
        );
        assertEquals("Missing JWT claims", ex.getMessage());
    }

    @Test
    void decodeEncodedListToRawBytes_throwsWhenBlank() {
        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> invokePrivate(service, "decodeEncodedListToRawBytes",
                        new Class<?>[]{String.class},
                        new Object[]{"   "})
        );
        assertEquals("encodedList cannot be blank", ex.getMessage());
    }

    @Test
    void readClaimsSafely_wrapsParseException() throws Exception {
        SignedJWT mocked = Mockito.mock(SignedJWT.class);
        Mockito.when(mocked.getJWTClaimsSet()).thenThrow(new ParseException("boom", 0));

        StatusListCredentialException ex = assertThrows(
                StatusListCredentialException.class,
                () -> invokePrivate(service, "readClaimsSafely",
                        new Class<?>[]{SignedJWT.class},
                        new Object[]{mocked})
        );
        assertEquals("Error reading JWT claims set", ex.getMessage());
        assertNotNull(ex.getCause());
        assertTrue(ex.getCause() instanceof ParseException);
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    private static String buildSignedJwt(String issuer, String statusPurpose, String encodedList) throws Exception {
        return buildSignedJwtWithIssuerClaim(issuer, statusPurpose, encodedList);
    }

    private static String buildSignedJwtWithIssuerClaim(Object issuerClaim, String statusPurpose, String encodedList) throws Exception {
        Map<String, Object> credentialSubject = new LinkedHashMap<>();
        credentialSubject.put("statusPurpose", statusPurpose);
        credentialSubject.put("encodedList", encodedList);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("issuer", issuerClaim)
                .claim("credentialSubject", credentialSubject)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        // 32+ bytes secret for HS256
        byte[] secret = "0123456789abcdef0123456789abcdef".getBytes();
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    private static String buildSignedJwtWithoutCredentialSubject(String issuer) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("issuer", issuer)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] secret = "0123456789abcdef0123456789abcdef".getBytes();
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    private static String buildSignedJwtMissingCredentialSubjectField(String issuer, String missingField) throws Exception {
        Map<String, Object> credentialSubject = new LinkedHashMap<>();
        if (!"statusPurpose".equals(missingField)) {
            credentialSubject.put("statusPurpose", "revocation");
        }
        if (!"encodedList".equals(missingField)) {
            credentialSubject.put("encodedList", multibaseBase64UrlGzipped(new byte[]{0x01}));
        }

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("issuer", issuer)
                .claim("credentialSubject", credentialSubject)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        byte[] secret = "0123456789abcdef0123456789abcdef".getBytes();
        jwt.sign(new MACSigner(secret));
        return jwt.serialize();
    }

    private static String multibaseBase64UrlGzipped(byte[] raw) throws Exception {
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(gzip(raw));
    }

    private static byte[] gzip(byte[] input) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(input);
            gzip.finish();
            return baos.toByteArray();
        }
    }

    private static void invokePrivate(Object target, String method, Class<?>[] paramTypes, Object[] args) {
        try {
            Method m = target.getClass().getDeclaredMethod(method, paramTypes);
            m.setAccessible(true);
            m.invoke(target, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(cause);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static <T extends Throwable> T assertThrows(Class<T> expected, Executable executable) {
        return org.junit.jupiter.api.Assertions.assertThrows(expected, executable);
    }
}

