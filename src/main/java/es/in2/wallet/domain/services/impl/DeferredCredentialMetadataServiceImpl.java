package es.in2.wallet.domain.services.impl;

import es.in2.wallet.domain.entities.DeferredCredentialMetadata;
import es.in2.wallet.domain.exceptions.NoSuchDeferredCredentialMetadataException;
import es.in2.wallet.domain.repositories.DeferredCredentialMetadataRepository;
import es.in2.wallet.domain.services.DeferredCredentialMetadataService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class DeferredCredentialMetadataServiceImpl implements DeferredCredentialMetadataService {

    private final DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;

    @Override
    public Mono<String> saveDeferredCredentialMetadata(
            String processId,
            String credentialId,
            String transactionId,
            String accessToken,
            String deferredEndpoint
    ) {
        Instant now = Instant.now();
        return deferredCredentialMetadataRepository.save(
                DeferredCredentialMetadata.builder()
                        .credentialId(credentialId)
                        .transactionId(UUID.fromString(transactionId))
                        .accessToken(accessToken)
                        .deferredEndpoint(deferredEndpoint)
                        .createdAt(now)
                        .updatedAt(now)
                .build())
                .then(Mono.just(credentialId))
                .doOnSuccess(savedCredentialId -> log.info("[Process ID: {}] Deferred credential metadata for credential ID {} saved successfully.", processId, savedCredentialId));
    }

    @Override
    public Mono<DeferredCredentialMetadata> getDeferredCredentialMetadataByCredentialId(
            String processId,
            String credentialId
    ) {
        return findOrError(credentialId)
                .doOnSuccess(metadata ->
                        log.info("[Process ID: {}] Found deferred credential metadata for credential ID {}.",
                                processId, credentialId)
                )
                .doOnError(error ->
                        log.error("[Process ID: {}] Error retrieving deferred credential metadata for credentialId {} - {}",
                                processId, credentialId, error.getMessage(), error)
                );
    }

    @Override
    public Mono<Void> deleteDeferredCredentialMetadataByCredentialId(
            String processId,
            String credentialId
    ) {
        return findOrError(credentialId)
                .flatMap(deferredCredentialMetadataRepository::delete)
                .then()
                .doOnSuccess(unused ->
                        log.info("[Process ID: {}] Deleted deferred credential metadata for credential ID {}.",
                                processId, credentialId)
                )
                .doOnError(error ->
                        log.error("[Process ID: {}] Error deleting deferred credential metadata for credentialId {} - {}",
                                processId, credentialId, error.getMessage(), error)
                );
    }

    @Override
    public Mono<Void> updateDeferredCredentialMetadataTransactionIdByCredentialId(
            String processId,
            String credentialId,
            String transactionId
    ) {
        return findOrError(credentialId)
                .flatMap(metadata -> {
                    metadata.setTransactionId(UUID.fromString(transactionId));
                    metadata.setUpdatedAt(Instant.now());
                    return deferredCredentialMetadataRepository.save(metadata);
                })
                .then()
                .doOnSuccess(unused ->
                        log.info("[Process ID: {}] Updated deferred credential metadata for credential ID {}.",
                                processId, credentialId)
                )
                .doOnError(error ->
                        log.error("[Process ID: {}] Error updating deferred credential metadata for credentialId {} - {}",
                                processId, credentialId, error.getMessage(), error)
                );
    }

    private Mono<DeferredCredentialMetadata> findOrError(String credentialId) {
        return deferredCredentialMetadataRepository.findByCredentialId(credentialId)
                .switchIfEmpty(Mono.error(new NoSuchDeferredCredentialMetadataException(
                        "No deferred credential metadata found for credentialId: " + credentialId
                )));
    }

}
