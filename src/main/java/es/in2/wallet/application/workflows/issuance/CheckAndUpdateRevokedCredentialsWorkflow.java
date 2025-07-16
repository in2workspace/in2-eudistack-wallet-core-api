package es.in2.wallet.application.workflows.issuance;

import reactor.core.publisher.Mono;

public interface CheckAndUpdateRevokedCredentialsWorkflow {
    Mono<Void> execute(String processId);
}
