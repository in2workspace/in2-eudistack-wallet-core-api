package es.in2.wallet.application.workflows.issuance.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.CredentialStatusResponse;
import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.entities.StatusListCredentialData;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.domain.services.StatusListCredentialService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class CheckAndUpdateStatusCredentialsWorkflowImpl implements CheckAndUpdateStatusCredentialsWorkflow {
    private final CredentialService credentialService;
    private final StatusListCredentialService statusListCredentialService;
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
        log.info("ProcessID: {} - Checking credentialId={}", processId, credential.getId());
        if (isCredentialExpired(credential)) {
            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.EXPIRED);
        }

        CredentialStatus credentialStatus = credentialService.getCredentialStatus(credential);
        if (credentialStatus == null || credentialStatus.statusListCredential() == null || credentialStatus.statusListIndex() == null || credentialStatus.type() == null) {
            log.debug("ProcessID: {} - Credential {} missing credentialStatus", processId, credential.getId());
            return Flux.empty();
        }

        String rawUrl = credentialStatus.statusListCredential();
        String listIndex = credentialStatus.statusListIndex().trim();
        String type = credentialStatus.type().trim();
        log.info("Type: " + type);

        Optional<URI> statusListUriOpt = parseAndValidateStatusListCredentialUri(processId, credential, rawUrl);
        if (statusListUriOpt.isEmpty()) {
            return Flux.empty();
        }

        URI statusListUri = statusListUriOpt.get();
        String cleanedUrl = statusListUri.toString();

        // legacy
        if (PLAIN_LIST_ENTITY.equals(type)) {
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
                    .onErrorResume(e -> Flux.empty());
        }

        if (BIT_STRING_STATUS_LIST_ENTRY.equals(type)) {
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

            Mono<byte[]> rawBytesMono = bitstringCache.computeIfAbsent(cleanedUrl, url -> {
                log.debug("ProcessID: {} - bitstringCache MISS url={} expectedPurpose={}", processId, url, REVOCATION);

                return getBitstringRawBytesFromIssuer(url, REVOCATION)
                        .doOnSuccess(bytes -> log.info("ProcessID: {} - Fetched bitstring bytes len={} from {}", processId, bytes.length, url))
                        .doOnError(e -> log.error("ProcessID: {} - Error fetching bitstring from {}: {}", processId, url, e.toString()))
                        .cache();
            });

            return rawBytesMono
                    .flatMapMany(rawBytes -> {
                        int maxBits = statusListCredentialService.maxBits(rawBytes);
                        if (index >= maxBits) {
                            log.warn("ProcessID: {} - statusListIndex out of range for credential {}. index={}, maxBits={}",
                                    processId, credential.getId(), index, maxBits);
                            return Flux.empty();
                        }

                        boolean revoked = statusListCredentialService.isBitSet(rawBytes, index);
                        log.info("ProcessID: {} - credentialId={} bitstring revoked={}", processId, credential.getId(), revoked);

                        if (revoked) {
                            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.REVOKED);
                        }

                        log.debug("ProcessID: {} - Credential {} not revoked (bitstring)", processId, credential.getId());
                        return Flux.empty();
                    })
                    .doOnError(e -> log.warn("ProcessID: {} - credentialId={} cannot verify bitstring status: {}",
                            processId, credential.getId(), e.toString()))
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

    private Mono<byte[]> getBitstringRawBytesFromIssuer(String statusListCredentialUrl, String expectedPurpose) {
        return webClient.centralizedWebClient()
                .get()
                .uri(statusListCredentialUrl)
                .header("Accept", "application/vc+jwt")
                .exchangeToMono(response -> {
                    HttpStatusCode status = response.statusCode();
                    if (status.isError()) {
                        return response.bodyToMono(String.class)
                                .defaultIfEmpty("")
                                .flatMap(body -> Mono.error(new WebClientResponseException(
                                        "Status list issuer returned error",
                                        status.value(),
                                        status.toString(),
                                        response.headers().asHttpHeaders(),
                                        body.getBytes(),
                                        null
                                )));
                    }
                    return response.bodyToMono(String.class);
                })
                .map(String::trim)
                .map(jwtString -> {
                    try {
                        StatusListCredentialData data = statusListCredentialService.parse(jwtString);
                        statusListCredentialService.validateStatusPurposeMatches(data.statusPurpose(), expectedPurpose);
                        return data.rawBitstringBytes();
                    } catch (Exception e) {
                        throw new ParseErrorException("Error parsing/validating StatusListCredential JWT: " + e.getMessage());
                    }
                })
                .doOnError(e -> {
                    if (e instanceof WebClientResponseException ex) {
                        log.warn("Bitstring issuer HTTP error. url={} status={} body={}",
                                statusListCredentialUrl, ex.getStatusCode(), safeBody(ex.getResponseBodyAsString()));
                    } else if (e instanceof WebClientRequestException) {
                        log.warn("Bitstring issuer request error. url={} message={}",
                                statusListCredentialUrl, e.getMessage());
                    } else if (e instanceof ParseErrorException) {
                        log.warn("Bitstring issuer parse/validation error. url={} message={}",
                                statusListCredentialUrl, e.getMessage());
                    } else {
                        log.warn("Bitstring issuer unexpected error. url={} message={}",
                                statusListCredentialUrl, e.toString());
                    }
                });
    }

    private Optional<URI> parseAndValidateStatusListCredentialUri(String processId, Credential credential, String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            log.warn("ProcessID: {} - Credential {} has blank statusListCredential URL",
                    processId, credential.getId());
            return Optional.empty();
        }

        final URI uri;
        try {
            uri = URI.create(rawUrl.trim());
        } catch (IllegalArgumentException e) {
            log.warn("ProcessID: {} - Credential {} has invalid statusListCredential URL '{}'",
                    processId, credential.getId(), rawUrl);
            return Optional.empty();
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            log.warn("ProcessID: {} - Credential {} statusListCredential URL is not HTTPS: '{}'",
                    processId, credential.getId(), rawUrl);
            return Optional.empty();
        }

        return Optional.of(uri);
    }

    private String safeBody(String body) {
        if (body == null) return "";
        int max = 500;
        return body.length() <= max ? body : body.substring(0, max) + "...";
    }

}
