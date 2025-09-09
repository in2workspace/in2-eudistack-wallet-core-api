package es.in2.wallet.domain.repositories;

import es.in2.wallet.domain.entities.Credential;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface CredentialRepository extends ReactiveCrudRepository<Credential, UUID> {
    Flux<Credential> findAllByUserId(UUID userId);
    Mono<Credential> findByCredentialId(String credentialId);
}