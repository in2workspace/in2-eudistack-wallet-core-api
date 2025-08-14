package es.in2.wallet.application.workflows.issuance;

import reactor.core.publisher.Mono;

public interface CheckAndUpdateStatusCredentialsWorkflow {
    Mono<Void> execute(String processId);
    Mono<Void> executeForUser(String processId, String userId);
}
