package es.in2.wallet.domain.services;

import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.dto.VerifiableCredential;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

public interface CredentialService {
    Mono<String> saveCredential(String processId, UUID userId, CredentialResponse credentialResponse, String format);
    Mono<Void> saveDeferredCredential(String processId, String userId, String credentialId, CredentialResponse credentialResponse);
    Mono<List<VerifiableCredential>> getCredentialsByUserId(String processId, String userId);
    Mono<String> extractDidFromCredential(String processId, String credentialId, String userId);
    Mono<Void> deleteCredential(String processId, String credentialId, String userId);
    Mono<List<VerifiableCredential>> getCredentialsByUserIdAndType(String processId, String userId, String requiredType);
    Mono<String> getCredentialDataByIdAndUserId(String processId, String userId, String credentialId);
}
