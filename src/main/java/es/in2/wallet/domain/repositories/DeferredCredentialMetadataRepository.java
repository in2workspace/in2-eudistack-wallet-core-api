package es.in2.wallet.domain.repositories;

import es.in2.wallet.domain.entities.DeferredCredentialMetadata;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface DeferredCredentialMetadataRepository extends ReactiveCrudRepository<DeferredCredentialMetadata, UUID> {
    Mono<DeferredCredentialMetadata> findByCredentialId(String credentialId);
}
