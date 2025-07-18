package es.in2.wallet.infrastructure.scheduler.services.impl;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import es.in2.wallet.infrastructure.scheduler.services.StatusCredentialSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusCredentialSyncServiceImpl implements StatusCredentialSyncService {

    private final CheckAndUpdateStatusCredentialsWorkflow checkAndUpdateStatusCredentialsWorkflow;

    @Override
    public Mono<Void> execute(String processId) {
        log.debug("ProcessID: {} - Status credential sync service started", processId);
        return checkAndUpdateStatusCredentialsWorkflow.execute(processId);
    }


}
