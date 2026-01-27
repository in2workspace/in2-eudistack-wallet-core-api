package es.in2.wallet.api.service;

import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.NotificationEvent;
import es.in2.wallet.domain.services.impl.NotificationClientServiceImpl;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationClientServiceImplTest {

    @Mock
    private WebClientConfig webClientConfig;

    @InjectMocks
    private NotificationClientServiceImpl service;

    @Test
    void notifyIssuer_shouldReturnError_whenNotificationIdIsNull() {
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        StepVerifier.create(service.notifyIssuer(
                        "processId",
                        "token",
                        null,
                        NotificationEvent.CREDENTIAL_ACCEPTED,
                        "desc",
                        metadata
                ))
                .expectErrorMatches(e ->
                        e instanceof IllegalArgumentException
                                && e.getMessage().contains("notificationId is required")
                )
                .verify();
    }

    @Test
    void notifyIssuer_shouldReturnError_whenNotificationIdIsBlank() {
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        StepVerifier.create(service.notifyIssuer(
                        "processId",
                        "token",
                        "   ",
                        NotificationEvent.CREDENTIAL_ACCEPTED,
                        "desc",
                        metadata
                ))
                .expectErrorMatches(e ->
                        e instanceof IllegalArgumentException
                                && e.getMessage().contains("notificationId is required")
                )
                .verify();
    }

    @Test
    void notifyIssuer_shouldReturnError_whenEventIsNull() {
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        StepVerifier.create(service.notifyIssuer(
                        "processId",
                        "token",
                        "notif-1",
                        null,
                        "desc",
                        metadata
                ))
                .expectErrorMatches(e ->
                        e instanceof IllegalArgumentException
                                && e.getMessage().contains("event is required")
                )
                .verify();
    }

    @Test
    void notifyIssuer_shouldComplete_whenIssuerReturns2xx() {
        // GIVEN
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        ClientResponse okResponse = ClientResponse.create(HttpStatus.OK)
                .body("")
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(okResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // WHEN
        Mono<Void> result = service.notifyIssuer(
                "processId",
                "access-token",
                "notif-1",
                NotificationEvent.CREDENTIAL_ACCEPTED,
                "some-description",
                metadata
        );

        // THEN
        StepVerifier.create(result)
                .verifyComplete();
    }

    @Test
    void notifyIssuer_shouldError_whenIssuerReturns4xx() {
        // GIVEN
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        ClientResponse badRequest = ClientResponse.create(HttpStatus.BAD_REQUEST)
                .body("error")
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(badRequest));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // WHEN
        Mono<Void> result = service.notifyIssuer(
                "processId",
                "access-token",
                "notif-1",
                NotificationEvent.CREDENTIAL_ACCEPTED,
                "some-description",
                metadata
        );

        // THEN
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void notifyIssuer_shouldError_whenIssuerReturns5xx() {
        // GIVEN
        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .notificationEndpoint("https://issuer.example/notify")
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        ClientResponse serverError = ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("error")
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(serverError));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // WHEN
        Mono<Void> result = service.notifyIssuer(
                "processId",
                "access-token",
                "notif-1",
                NotificationEvent.CREDENTIAL_ACCEPTED,
                "some-description",
                metadata
        );

        // THEN
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }
}
