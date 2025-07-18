package es.in2.wallet.application.workflows.issuance.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.wallet.domain.utils.ApplicationConstants.BEARER;
import static es.in2.wallet.domain.utils.ApplicationConstants.HEADER_AUTHORIZATION;

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

        return credentialService.getAllCredentials()
                .flatMapMany(Flux::fromIterable)
                .flatMap(credential -> {
                    if (isCredentialExpired(credential)) {
                        return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.EXPIRED);
                    }

                    CredentialStatus credentialStatus = credentialService.getCredentialStatus(credential);
                    if (credentialStatus == null || credentialStatus.statusListCredential() == null) {
                        log.debug("ProcessID: {} - Credential {} missing credentialStatus", processId, credential.getId());
                        return Flux.empty();
                    }

                    String url = credentialStatus.statusListCredential();
                    String index = credentialStatus.statusListIndex();

                    Mono<List<String>> revokedNoncesMono = nonceCache.computeIfAbsent(url, k -> getRevokedNoncesFromIssuer(k).cache());

                    return revokedNoncesMono.flatMapMany(nonces -> {
                        boolean isRevoked = nonces.contains(index);
                        if (isRevoked) {
                            return updateCredentialStatusIfNecessary(processId, credential, LifeCycleStatus.REVOKED);
                        }
                        log.debug("ProcessID: {} - Credential {} not revoked", processId, credential.getId());
                        return Flux.empty();
                    });
                })
                .then();
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
                .header(HEADER_AUTHORIZATION, BEARER)
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


}
