package es.in2.wallet.application.workflows.data;

import es.in2.wallet.application.dto.CredentialsBasicInfo;
import reactor.core.publisher.Mono;

import java.util.List;

public interface DataWorkflow {
    Mono<List<CredentialsBasicInfo>> getAllCredentialsByUserId(String processId, String userId);
    Mono<Void> deleteCredentialByIdAndUserId(String processId, String credentialId, String userId);
}
