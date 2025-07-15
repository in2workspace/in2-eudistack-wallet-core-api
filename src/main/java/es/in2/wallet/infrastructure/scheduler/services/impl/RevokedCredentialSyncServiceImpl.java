package es.in2.wallet.infrastructure.scheduler.services.impl;

import es.in2.wallet.application.ports.AppConfig;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import es.in2.wallet.infrastructure.scheduler.services.RevokedCredentialSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE;
import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE_APPLICATION_JSON;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevokedCredentialSyncServiceImpl implements RevokedCredentialSyncService {

    private final WebClientConfig webClient;
    private final AppConfig appConfig;

    @Override
    public Mono<Void> execute(String processId) {
        getRevokeStatusCredentialsListMetadata()
            .doOnSuccess(response -> log.info("ProcessID: {} - Revoke status credentials list metadata response: {}", processId, response))
            .onErrorResume(e -> {
                log.error("ProcessID: {} - Error while fetching Revoke Status Credentials List Metadata from the Issuer: {}", processId, e.getMessage());
                return Mono.error(new RuntimeException("Error while fetching Revoke Status Credentials List Metadata from the Issuer"));
            });
        return Mono.empty();

    }

    private Mono<String> getRevokeStatusCredentialsListMetadata() {
        //TODO: Hardcoded for now
        String statusListCredentialIssuerURL = "https://issuer-dev.in2.ssihub.org/credentials/status/1";
        return webClient.centralizedWebClient()
                .get()
                .uri(statusListCredentialIssuerURL)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .exchangeToMono(response -> {
                    if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                        return Mono.error(new RuntimeException("Error while fetching Revoke Status Credentials List Metadata from the Issuer, error" + response));
                    }
                    else {
                        log.info("Revoke status credentials list metadata: {}", response);
                        return response.bodyToMono(String.class);
                    }
                });
    }
}
