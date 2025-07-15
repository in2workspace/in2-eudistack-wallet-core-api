package es.in2.wallet.infrastructure.scheduler.services;

import reactor.core.publisher.Mono;

public interface RevokedCredentialSyncService {
    Mono<Void> execute(String processId);

}
