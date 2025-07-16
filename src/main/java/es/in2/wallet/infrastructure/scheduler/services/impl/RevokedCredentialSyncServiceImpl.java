package es.in2.wallet.infrastructure.scheduler.services.impl;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateRevokedCredentialsWorkflow;
import es.in2.wallet.infrastructure.scheduler.services.RevokedCredentialSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevokedCredentialSyncServiceImpl implements RevokedCredentialSyncService {

    private final CheckAndUpdateRevokedCredentialsWorkflow checkAndUpdateRevokedCredentialsWorkflow;

    @Override
    public Mono<Void> execute(String processId) {
        log.debug("ProcessID: {} - Revoked credential sync service started", processId);
        return checkAndUpdateRevokedCredentialsWorkflow.execute(processId);
    }


}
