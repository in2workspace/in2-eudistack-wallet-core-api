package es.in2.wallet.domain.services;

import es.in2.wallet.domain.entities.DeferredCredentialMetadata;
import reactor.core.publisher.Mono;


public interface DeferredCredentialMetadataService {
    Mono<String> saveDeferredCredentialMetadata(String processId, String credentialId, String transactionId, String accessToken, String deferredEndpoint);
    Mono<DeferredCredentialMetadata> getDeferredCredentialMetadataByCredentialId(String processId, String credentialId);
    Mono<Void> deleteDeferredCredentialMetadataByCredentialId(String processId, String credentialId);
    Mono<Void> updateDeferredCredentialMetadataTransactionIdByCredentialId(String processId, String credentialId, String transactionId);
}
