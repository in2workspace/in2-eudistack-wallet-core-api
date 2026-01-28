package es.in2.wallet.domain.services;

import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.CredentialResponseWithStatus;
import es.in2.wallet.application.dto.TokenInfo;
import reactor.core.publisher.Mono;


public interface OID4VCIDeferredCredentialService {
    Mono<CredentialResponseWithStatus> handleDeferredCredential(
            TokenInfo tokenInfo,
            String tokenEndpoint,
            String transactionId,
            Long interval,
            CredentialIssuerMetadata credentialIssuerMetadata
    );
}
