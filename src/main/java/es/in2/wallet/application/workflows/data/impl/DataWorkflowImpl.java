package es.in2.wallet.application.workflows.data.impl;

import es.in2.wallet.application.dto.CredentialsBasicInfo;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.ports.VaultService;
import es.in2.wallet.application.workflows.data.DataWorkflow;
import es.in2.wallet.domain.services.CredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DataWorkflowImpl implements DataWorkflow {

    private final CredentialService credentialService;
    private final VaultService vaultService;

    /**
     * Retrieves a list of basic information about the verifiable credentials (VCs) associated with a given user ID.
     *
     * @param processId A unique identifier for the process, used for logging and tracking.
     * @param userId    The unique identifier of the user whose VCs are to be retrieved.
     */
    @Override
    public Mono<List<VerifiableCredential>> getAllCredentialsByUserId(String processId, String userId) {
        return credentialService.getCredentialsByUserId(processId, userId)
                .doOnSuccess(list -> log.info("Retrieved VCs for userId: {}", userId))
                .doOnError(error ->
                        log.error("Error while retrieving VCs for userId: {}", userId, error)
                )
                .onErrorResume(Mono::error);
    }

    /**
     * Deletes a specific verifiable credential (VC) by its ID for a given user.
     * This method first retrieves the requested credential associated with the user. If the credential is found, it then
     * extracts the Decentralized Identifier (DID) from the VC, deletes the secret key associated with the DID
     * in the vault, and finally deletes the VC itself.
     *
     * @param processId    A unique identifier for the process, used for logging and tracking.
     * @param credentialId The unique identifier of the credential to be deleted.
     * @param userId       The unique identifier of the user from whom the VC is to be deleted.
     */

    @Override
    public Mono<Void> deleteCredentialByIdAndUserId(String processId, String credentialId, String userId) {
        return credentialService.extractDidFromCredential(processId, credentialId, userId)
                .flatMap(vaultService::deleteSecretByKey)
                .then(credentialService.deleteCredential(processId, credentialId, userId))
                .doOnSuccess(aVoid -> log.info("Delete VC with Id: {} successfully completed", credentialId))
                .onErrorResume(Mono::error);
    }


}
