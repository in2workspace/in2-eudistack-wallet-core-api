package es.in2.wallet.domain.services;

import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.CredentialResponseWithStatus;
import es.in2.wallet.application.dto.TokenResponse;
import reactor.core.publisher.Mono;


public interface OID4VCICredentialService {
    Mono<CredentialResponseWithStatus> getCredential(String jwt, TokenResponse tokenResponse, Long tokenObtainedAt, String tokenEndpoint, CredentialIssuerMetadata credentialIssuerMetadata, String format, String credentialConfigurationId);
    Mono<CredentialResponseWithStatus> getCredentialDomeDeferredCase(String transactionId, String accessToken, String deferredEndpoint);
    String getNonceValue();
}
