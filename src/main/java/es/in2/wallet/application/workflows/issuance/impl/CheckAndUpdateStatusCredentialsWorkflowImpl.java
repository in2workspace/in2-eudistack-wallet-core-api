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

    private Flux<Credential> handleCredentialStatusCheck(
            String processId,
            Credential credential,
            Map<String, Mono<List<String>>> nonceCache,
            Map<String, Mono<byte[]>> bitstringCache
    ) {
        log.info("ProcessID: {} - Checking credentialId={}", processId, credential.getId());

        if (isCredentialExpired(credential)) {
            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.EXPIRED);
        }

        Optional<StatusListCheckData> dataOpt = buildStatusListCheckData(processId, credential);
        if (dataOpt.isEmpty()) {
            return Flux.empty();
        }

        StatusListCheckData data = dataOpt.get();

        if (PLAIN_LIST_ENTITY.equals(data.type())) {
            return handleLegacyPlainList(processId, credential, data, nonceCache);
        }

        if (BIT_STRING_STATUS_LIST_ENTRY.equals(data.type())) {
            return handleBitstringStatusList(processId, credential, data, bitstringCache);
        }

        log.warn("ProcessID: {} - Unsupported credentialStatus.type '{}' for credential {}",
                processId, data.type(), credential.getId());
        return Flux.empty();
    }

    private Optional<StatusListCheckData> buildStatusListCheckData(String processId, Credential credential) {
        CredentialStatus credentialStatus = credentialService.getCredentialStatus(credential);
        if (credentialStatus == null
                || credentialStatus.statusListCredential() == null
                || credentialStatus.statusListIndex() == null
                || credentialStatus.type() == null) {
            log.debug("ProcessID: {} - Credential {} missing credentialStatus", processId, credential.getId());
            return Optional.empty();
        }

        String rawUrl = credentialStatus.statusListCredential();
        String listIndex = credentialStatus.statusListIndex().trim();
        String type = credentialStatus.type().trim();

        Optional<URI> statusListUriOpt = parseAndValidateStatusListCredentialUri(processId, credential, rawUrl);
        if (statusListUriOpt.isEmpty()) {
            return Optional.empty();
        }

        String cleanedUrl = statusListUriOpt.get().toString();
        return Optional.of(new StatusListCheckData(cleanedUrl, listIndex, type));
    }

    private Flux<Credential> handleLegacyPlainList(
            String processId,
            Credential credential,
            StatusListCheckData data,
            Map<String, Mono<List<String>>> nonceCache
    ) {
        Mono<List<String>> revokedNoncesMono = nonceCache.computeIfAbsent(data.cleanedUrl(), url ->
                getRevokedNoncesFromIssuer(url)
                        .doOnError(e -> log.error("ProcessID: {} - Error fetching nonces from {}: {}", processId, url, e.toString()))
                        .cache()
        );

        return revokedNoncesMono
                .flatMapMany(nonces -> {
                    boolean isRevoked = nonces.contains(data.listIndex());
                    if (isRevoked) {
                        return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.REVOKED);
                    }
                    log.debug("ProcessID: {} - Credential {} not revoked (legacy)", processId, credential.getId());
                    return Flux.empty();
                })
                .onErrorResume(e -> Flux.empty());
    }

    private Flux<Credential> handleBitstringStatusList(
            String processId,
            Credential credential,
            StatusListCheckData data,
            Map<String, Mono<byte[]>> bitstringCache
    ) {
        OptionalInt indexOpt = parseNonNegativeInt(data.listIndex(), processId, credential);
        if (indexOpt.isEmpty()) {
            return Flux.empty();
        }

        int index = indexOpt.getAsInt();

        Mono<byte[]> rawBytesMono = bitstringCache.computeIfAbsent(data.cleanedUrl(), url -> fetchBitstringBytes(processId, url));

        return rawBytesMono
                .flatMapMany(rawBytes -> verifyBitstringIndexAndUpdate(processId, credential, rawBytes, index))
                .doOnError(e -> log.warn("ProcessID: {} - credentialId={} cannot verify bitstring status: {}",
                        processId, credential.getId(), e.toString()))
                .onErrorResume(e -> Flux.empty());
    }

    private OptionalInt parseNonNegativeInt(String value, String processId, Credential credential) {
        final int index;
        try {
            index = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            log.error("ProcessID: {} - Invalid statusListIndex '{}' for credential {}",
                    processId, value, credential.getId());
            return OptionalInt.empty();
        }

        if (index < 0) {
            log.error("ProcessID: {} - statusListIndex must be >= 0 for credential {}",
                    processId, credential.getId());
            return OptionalInt.empty();
        }

        return OptionalInt.of(index);
    }

    private Mono<byte[]> fetchBitstringBytes(String processId, String url) {
        log.debug("ProcessID: {} - bitstringCache MISS url={} expectedPurpose={}", processId, url, REVOCATION);

        return getBitstringRawBytesFromIssuer(url, REVOCATION)
                .doOnSuccess(bytes -> log.info("ProcessID: {} - Fetched bitstring bytes len={} from {}", processId, bytes.length, url))
                .doOnError(e -> log.error("ProcessID: {} - Error fetching bitstring from {}: {}", processId, url, e.toString()))
                .cache();
    }

    private Flux<Credential> verifyBitstringIndexAndUpdate(
            String processId,
            Credential credential,
            byte[] rawBytes,
            int index
    ) {
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

    private record StatusListCheckData(
            String cleanedUrl,
            String listIndex,
            String type
    ) {}

}