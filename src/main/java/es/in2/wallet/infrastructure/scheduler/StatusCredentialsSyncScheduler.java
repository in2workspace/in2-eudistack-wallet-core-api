package es.in2.wallet.infrastructure.scheduler;


import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class StatusCredentialsSyncScheduler {

    private final CheckAndUpdateStatusCredentialsWorkflow checkAndUpdateStatusCredentialsWorkflow;

    @Scheduled(cron = "0 0 0 * * *")
    public void syncStatusCredentials() {
        String processId = UUID.randomUUID().toString();
        log.debug("ProcessID: {} - Starting scheduled sync of credential statuses", processId);

        checkAndUpdateStatusCredentialsWorkflow.execute(processId)
                .doOnError(e -> log.error("ProcessID: {} - Error during scheduled sync: {}", processId, e.getMessage(), e))
                .subscribe();
    }
}