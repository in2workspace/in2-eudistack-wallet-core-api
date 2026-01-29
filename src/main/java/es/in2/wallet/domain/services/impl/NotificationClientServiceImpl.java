package es.in2.wallet.domain.services.impl;

import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.NotificationEvent;
import es.in2.wallet.application.dto.NotificationRequest;
import es.in2.wallet.domain.services.NotificationClientService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.wallet.domain.utils.ApplicationConstants.BEARER;
import static es.in2.wallet.domain.utils.ApplicationConstants.HEADER_AUTHORIZATION;


@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationClientServiceImpl implements NotificationClientService {

    private final WebClientConfig webClient;

    @Override
    public Mono<Void> notifyIssuer(String processId, String bearerToken, String notificationId, NotificationEvent event, String description, CredentialIssuerMetadata credentialIssuerMetadata) {

        if (notificationId == null || notificationId.isBlank()) {
            return Mono.error(new IllegalArgumentException("notificationId is required"));
        }
        if (event == null) {
            return Mono.error(new IllegalArgumentException("event is required"));
        }
        NotificationRequest notificationRequest = NotificationRequest.builder()
                .notificationId(notificationId)
                .event(event)
                .eventDescription(description)
                .build();

        return webClient.centralizedWebClient()
                .post()
                .uri(credentialIssuerMetadata.notificationEndpoint())
                .header(HEADER_AUTHORIZATION, BEARER + bearerToken)
                .bodyValue(notificationRequest)
                .exchangeToMono(response -> {
                    if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                        return Mono.error(new RuntimeException(
                                "Error during the notification request, error: " + response
                        ));
                    } else {
                        log.info("Notification response retrieved");
                        return Mono.empty();
                    }
                })
                .then();
    }
}