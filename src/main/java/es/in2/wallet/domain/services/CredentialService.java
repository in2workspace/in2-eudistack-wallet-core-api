package es.in2.wallet.domain.services;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

public interface CredentialService {
    Mono<String> saveCredential(String processId, UUID userId, CredentialResponse credentialResponse, String format);
    Mono<Void> saveDeferredCredential(String processId, String userId, String credentialId, CredentialResponse credentialResponse);
    Mono<List<Credential>> getAllCredentials();
    CredentialStatus getCredentialStatus(Credential credential);
    JsonNode getCredentialJsonVc(Credential credential);

    Mono<List<VerifiableCredential>> getCredentialsByUserId(String processId, String userId);
    Mono<String> extractDidFromCredential(String processId, String credentialId, String userId);
    Mono<Void> deleteCredential(String processId, String credentialId, String userId);
    Mono<Credential> updateCredentialEntityLifeCycleStatus(Credential existingCredential, LifeCycleStatus lifeCycleStatus);

    Mono<List<VerifiableCredential>> getCredentialsByUserIdAndType(String processId, String userId, String requiredType);
    Mono<String> getCredentialDataByIdAndUserId(String processId, String userId, String credentialId);
}
