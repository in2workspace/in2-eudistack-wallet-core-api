package es.in2.wallet.application.workflows.issuance.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.CredentialStatusResponse;
import es.in2.wallet.application.workflows.issuance.CheckAndUpdateRevokedCredentialsWorkflow;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.wallet.domain.utils.ApplicationConstants.BEARER;
import static es.in2.wallet.domain.utils.ApplicationConstants.HEADER_AUTHORIZATION;

@Slf4j
@Service
@RequiredArgsConstructor
public class CheckAndUpdateRevokedCredentialsWorkflowImpl implements CheckAndUpdateRevokedCredentialsWorkflow {
    private final CredentialService credentialService;
    private final ObjectMapper objectMapper;
    private final WebClientConfig webClient;

    @Override
    public Mono<Void> execute(String processId) {
        Map<String, Mono<List<String>>> nonceCache = new ConcurrentHashMap<>();

        return credentialService.getAllCredentials()
                .flatMapMany(Flux::fromIterable)
                .flatMap(credential -> {
                    CredentialStatus credentialStatus = credentialService.getCredentialStatus(credential);

                    if (credentialStatus == null || credentialStatus.statusListCredential() == null) {
                        log.debug("ProcessID: {} - Credential {} does not contain credentialStatus info", processId, credential.getId());
                        return Mono.empty();
                    }

                    String statusListCredentialUrl = credentialStatus.statusListCredential();
                    String statusListIndex = credentialStatus.statusListIndex();

                    Mono<List<String>> noncesMono = nonceCache.computeIfAbsent(
                            statusListCredentialUrl,
                            url -> getRevokedNoncesFromIssuer(url).cache()
                    );

                    return noncesMono.flatMapMany(nonces -> {
                        boolean isRevoked = nonces.contains(statusListIndex);

                        if (isRevoked && !LifeCycleStatus.REVOKED.toString().equalsIgnoreCase(credential.getCredentialStatus())) {
                            log.info("ProcessID: {} - Credential {} marked as revoked", processId, credential.getId());
                            return credentialService.updateCredentialEntityLifeCycleToRevoke(credential).flux();
                        } else {
                            log.debug("ProcessID: {} - Credential {} not updated (revoked: {}, current status: {})",
                                    processId, credential.getId(), isRevoked, credential.getCredentialStatus());
                            return Flux.empty();
                        }
                    });
                })
                .then();
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
                                .map(jsonBody -> {
                                    try {
                                        CredentialStatusResponse[] responseArray = objectMapper.readValue(jsonBody, CredentialStatusResponse[].class);
                                        return Arrays.stream(responseArray)
                                                .map(CredentialStatusResponse::credentialNonce)
                                                .toList();
                                    } catch (Exception e) {
                                        log.error("Error parsing JSON response from {}: {}", statusListCredentialUrl, e.getMessage());
                                        throw new ParseErrorException("JSON parse error");
                                    }
                                });
                    }
                });
    }


}
