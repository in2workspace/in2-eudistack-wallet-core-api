package es.in2.wallet.domain.services;


import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.NotificationEvent;
import reactor.core.publisher.Mono;

public interface NotificationClientService {
    Mono<Void> notifyIssuer(String processId, String bearerToken, String notificationId, NotificationEvent event, String description, CredentialIssuerMetadata credentialIssuerMetadata);
}
