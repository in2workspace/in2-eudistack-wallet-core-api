package es.in2.wallet.application.workflows.issuance.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.CredentialStatusResponse;
import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPInputStream;


@Slf4j
@Service
@RequiredArgsConstructor
public class CheckAndUpdateStatusCredentialsWorkflowImpl implements CheckAndUpdateStatusCredentialsWorkflow {
    private final CredentialService credentialService;
    private final ObjectMapper objectMapper;
    private final WebClientConfig webClient;

    @Override
    public Mono<Void> execute(String processId) {
        Map<String, Mono<List<String>>> nonceCache = new ConcurrentHashMap<>();
        Map<String, Mono<byte[]>> bitstringCache = new ConcurrentHashMap<>();

        return credentialService.getAllCredentials()
                .flatMapMany(Flux::fromIterable)
                .filter(credential -> {
                    String status = credential.getCredentialStatus();
                    return status != null && status.equalsIgnoreCase(LifeCycleStatus.VALID.toString());
                })
                .flatMap(credential -> handleCredentialStatusCheck(processId, credential, nonceCache, bitstringCache))
                .then();
    }
    @Override
    public Mono<Void> executeForUser(String processId, String userId) {
        Map<String, Mono<List<String>>> nonceCache = new ConcurrentHashMap<>();
        Map<String, Mono<byte[]>> bitstringCache = new ConcurrentHashMap<>();

        return credentialService.getAllCredentialsByUser(userId)
                .flatMapMany(Flux::fromIterable)
                .filter(credential -> {
                    String status = credential.getCredentialStatus();
                    return status != null && status.equalsIgnoreCase(LifeCycleStatus.VALID.toString());
                })
                .flatMap(credential -> handleCredentialStatusCheck(processId, credential, nonceCache, bitstringCache))
                .then();
    }


    private Flux<Credential> handleCredentialStatusCheck(String processId, Credential credential, Map<String, Mono<List<String>>> nonceCache, Map<String, Mono<byte[]>> bitstringCache) {
        log.info("Process ID: {}, handleCredentialStatusCheck - credential: {}", processId, credential);
        if (isCredentialExpired(credential)) {
            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.EXPIRED);
        }

        CredentialStatus credentialStatus = credentialService.getCredentialStatus(credential);
        if (credentialStatus == null || credentialStatus.statusListCredential() == null || credentialStatus.statusListIndex() == null || credentialStatus.type() == null) {
            log.debug("ProcessID: {} - Credential {} missing credentialStatus", processId, credential.getId());
            return Flux.empty();
        }

        String rawUrl = credentialStatus.statusListCredential().trim();
        String listIndex = credentialStatus.statusListIndex().trim();
        String type = credentialStatus.type().trim();
        log.info("Type: " + type);

        if (!isValidStatusListCredentialUrl(processId, credential, rawUrl)) {
            return Flux.empty();
        }

        String cleanedUrl = URI.create(rawUrl.trim()).toString();

        // legacy
        if ("PlainListEntity".equals(type)) {
            Mono<List<String>> revokedNoncesMono = nonceCache.computeIfAbsent(cleanedUrl, k ->
                    getRevokedNoncesFromIssuer(k)
                            .doOnError(e -> log.error("ProcessID: {} - Error fetching nonces from {}: {}", processId, k, e.toString()))
                            .cache()
            );

            return revokedNoncesMono
                    .flatMapMany(nonces -> {
                        boolean isRevoked = nonces.contains(listIndex);
                        if (isRevoked) {
                            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.REVOKED);
                        }
                        log.debug("ProcessID: {} - Credential {} not revoked (legacy)", processId, credential.getId());
                        return Flux.empty();
                    })
                    // If we cannot fetch/parse the list, do nothing (no status change).
                    .onErrorResume(e -> Flux.empty());
        }

        if ("BitstringStatusListEntry".equals(type)) {
            final int index;
            try {
                index = Integer.parseInt(listIndex);
            } catch (NumberFormatException e) {
                log.error("ProcessID: {} - Invalid statusListIndex '{}' for credential {}",
                        processId, listIndex, credential.getId());
                return Flux.empty();
            }

            if (index < 0) {
                log.error("ProcessID: {} - statusListIndex must be >= 0 for credential {}",
                        processId, credential.getId());
                return Flux.empty();
            }

            Mono<byte[]> rawBytesMono = bitstringCache.computeIfAbsent(cleanedUrl, url ->
                    getBitstringRawBytesFromIssuer(url)
                            .doOnError(e -> log.error("ProcessID: {} - Error fetching bitstring from {}: {}", processId, url, e.toString()))
                            .cache()
            );

            return rawBytesMono
                    .flatMapMany(rawBytes -> {
                        int maxBits = rawBytes.length * 8;
                        if (index >= maxBits) {
                            log.warn("ProcessID: {} - statusListIndex out of range for credential {}. index={}, maxBits={}",
                                    processId, credential.getId(), index, maxBits);
                            return Flux.empty();
                        }

                        boolean revoked = isBitSet(rawBytes, index);
                        log.info("Revoked? " + revoked);
                        if (revoked) {
                            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.REVOKED);
                        }

                        log.debug("ProcessID: {} - Credential {} not revoked (bitstring)", processId, credential.getId());
                        return Flux.empty();
                    })
                    // If we cannot fetch/parse the list, do nothing (no status change).
                    .onErrorResume(e -> Flux.empty());
        }


        log.warn("ProcessID: {} - Unsupported credentialStatus.type '{}' for credential {}",
                processId, type, credential.getId());
        return Flux.empty();
    }


    private boolean isCredentialExpired(Credential credential) {
        JsonNode vcJson = credentialService.getCredentialJsonVc(credential);
        if (vcJson == null || vcJson.get("validUntil") == null) {
            return false;
        }
        try {
            Instant validUntil = Instant.parse(vcJson.get("validUntil").asText());
            return Instant.now().isAfter(validUntil);
        } catch (Exception e) {
            log.warn("Invalid 'validUntil' format for credential {}: {}", credential.getId(), e.getMessage());
            return false;
        }
    }

    private Flux<Credential> updateCredentialStatusIfNecessary(String processId,Credential credential,LifeCycleStatus newStatus) {
        String currentStatus = credential.getCredentialStatus();
        if (!newStatus.toString().equalsIgnoreCase(currentStatus)) {
            log.info("ProcessID: {} - Credential {} marked as {}", processId, credential.getId(), newStatus);
            return credentialService.updateCredentialEntityLifeCycleStatus(credential, newStatus).flux();
        } else {
            log.debug("ProcessID: {} - Credential {} already in status {}", processId, credential.getId(), currentStatus);
            return Flux.empty();
        }
    }


    private Mono<List<String>> getRevokedNoncesFromIssuer(String statusListCredentialUrl) {
        log.debug("Fetching revoked nonces from: {}", statusListCredentialUrl);

        return webClient.centralizedWebClient()
                .get()
                .uri(statusListCredentialUrl)
                .exchangeToMono(response -> {
                    if (response.statusCode().isError()) {
                        return response.bodyToMono(String.class)
                                .flatMap(errorBody -> {
                                    log.error("Error fetching revoked nonces from {}: {}", statusListCredentialUrl, errorBody);
                                    return Mono.error(new RuntimeException("Issuer call failed: " + errorBody));
                                });
                    } else {
                        return response.bodyToMono(String.class)
                                .flatMap(jsonBody -> {
                                    try {
                                        CredentialStatusResponse[] responseArray = objectMapper.readValue(jsonBody, CredentialStatusResponse[].class);
                                        List<String> nonces = Arrays.stream(responseArray)
                                                .map(CredentialStatusResponse::credentialNonce)
                                                .toList();
                                        return Mono.just(nonces);
                                    } catch (Exception e) {
                                        log.error("Error parsing JSON response from {}: {}", statusListCredentialUrl, e.getMessage(), e);
                                        return Mono.error(new ParseErrorException("JSON parse error"));
                                    }
                                });

                    }
                });
    }

    private Mono<byte[]> getBitstringRawBytesFromIssuer(String statusListCredentialUrl) {
        return webClient.centralizedWebClient()
                .get()
                .uri(statusListCredentialUrl)
                .header("Accept", "application/vc+jwt")
                .retrieve()
                .bodyToMono(String.class)
                .map(jwtString -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwtString);

                        JsonNode claims = objectMapper.valueToTree(
                                signedJWT.getJWTClaimsSet().toJSONObject()
                        );

                        JsonNode credentialSubject = claims.get("credentialSubject");
                        if (credentialSubject == null || credentialSubject.isNull()) {
                            throw new ParseErrorException("Missing credentialSubject");
                        }

                        JsonNode encodedListNode = credentialSubject.get("encodedList");
                        if (encodedListNode == null || !encodedListNode.isTextual() || encodedListNode.asText().isBlank()) {
                            throw new ParseErrorException("Missing or invalid encodedList");
                        }

                        return decodeEncodedListToRawBytes(encodedListNode.asText());

                    } catch (ParseException e) {
                        throw new ParseErrorException("Invalid JWT format: " + e.getMessage());
                    } catch (Exception e) {
                        // Keep a single failure mode for this path
                        throw new ParseErrorException("Error parsing StatusListCredential JWT: " + e.getMessage());
                    }
                });
    }


    public static byte[] decodeEncodedListToRawBytes(String encodedList) {
        if (encodedList == null || encodedList.isBlank()) {
            throw new IllegalArgumentException("encodedList cannot be blank");
        }

        String payload = encodedList.trim();
        if (payload.charAt(0) != 'u') {
            throw new IllegalArgumentException("encodedList must start with multibase base64url prefix 'u'");
        }

        byte[] gzipped = Base64.getUrlDecoder().decode(payload.substring(1));
        return gunzip(gzipped);
    }

    public static boolean isBitSet(byte[] rawBytes, int bitIndex) {
        log.info("isBitSet - bitIndex: " + bitIndex);
        if (rawBytes == null) {
            throw new IllegalArgumentException("rawBytes cannot be null");
        }
        if (bitIndex < 0) {
            throw new IllegalArgumentException("bitIndex must be >= 0");
        }

        int maxBits = rawBytes.length * 8;
        if (bitIndex >= maxBits) {
            throw new IllegalArgumentException("bitIndex out of range. maxBits=" + maxBits + ", bitIndex=" + bitIndex);
        }

        // LSB-first in each byte
        int byteIndex = bitIndex / 8;
        int bitInByte = bitIndex % 8;
        int mask = 1 << bitInByte;

        return (rawBytes[byteIndex] & mask) != 0;
    }

    private static byte[] gunzip(byte[] input) {
        log.info("gunzip");
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
            throw new IllegalStateException("Failed to gunzip content: " + e.getMessage(), e);
        }
    }

    private boolean isValidStatusListCredentialUrl(String processId, Credential credential, String rawUrl) {
        log.info("Validating statusListCredential URL: {}", rawUrl);
        if (rawUrl == null || rawUrl.isBlank()) {
            log.warn("ProcessID: {} - Credential {} has blank statusListCredential URL",
                    processId, credential.getId());
            return false;
        }

        final URI uri;
        try {
            uri = URI.create(rawUrl.trim());
        } catch (IllegalArgumentException e) {
            log.warn("ProcessID: {} - Credential {} has invalid statusListCredential URL '{}'",
                    processId, credential.getId(), rawUrl);
            return false;
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            log.warn("ProcessID: {} - Credential {} statusListCredential URL is not HTTPS: '{}'",
                    processId, credential.getId(), rawUrl);
            return false;
        }

        return true;
    }



}
