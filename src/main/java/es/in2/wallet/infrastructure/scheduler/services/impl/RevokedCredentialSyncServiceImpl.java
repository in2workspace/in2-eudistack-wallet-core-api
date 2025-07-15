package es.in2.wallet.infrastructure.scheduler.services.impl;

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

    @Override
    public Mono<Void> execute(String processId) {
        return getRevokeStatusCredentialsListMetadata()
            .doOnSuccess(response -> log.info("ProcessID: {} - Revoke status credentials list metadata response: {}", processId, response))
            .onErrorResume(e -> {
                log.error("ProcessID: {} - Error while fetching Revoke Status Credentials List Metadata from the Issuer: {}", processId, e.getMessage());
                return Mono.error(new RuntimeException("Error while fetching Revoke Status Credentials List Metadata from the Issuer"));
            }).then();

    }

    private Mono<String> getRevokeStatusCredentialsListMetadata() {
        //TODO: Hardcoded for now
        String statusListCredentialIssuerURL = "https://issuer-dev.in2.ssihub.org/backoffice/v1/credentials/status/1";
        return webClient.centralizedWebClient()
                .get()
                .uri(statusListCredentialIssuerURL)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .exchangeToMono(response -> {
                    if (response.statusCode().isError()) {
                        return response.bodyToMono(String.class)
                                .defaultIfEmpty("No body")
                                .flatMap(errorBody -> {
                                    log.error("Error response body: {}", errorBody);
                                    return Mono.error(new RuntimeException("Error from issuer: " + errorBody));
                                });
                    } else {
                        return response.bodyToMono(String.class)
                                .doOnNext(body ->
                                        log.debug("Received status list body: {}", body)
                                );
                    }
                });
    }

}
