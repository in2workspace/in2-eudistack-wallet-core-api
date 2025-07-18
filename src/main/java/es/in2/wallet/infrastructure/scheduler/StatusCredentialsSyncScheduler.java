package es.in2.wallet.infrastructure.scheduler;


import es.in2.wallet.infrastructure.scheduler.services.StatusCredentialSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class StatusCredentialsSyncScheduler {

    private final StatusCredentialSyncService revokedCredentialSyncService;

    //@Scheduled(cron = "0 0 0 * * *", zone = "Europe/Madrid")
    @Scheduled(cron = "0 0 */5 * * *", zone = "Europe/Madrid")
    public void syncStatusCredentials() {
        log.debug("Syncing status credentials");
        String processId = UUID.randomUUID().toString();
        revokedCredentialSyncService.execute(processId)
                .doOnError(e -> log.error("Error during scheduled sync: {}", e.getMessage(), e))
                .subscribe();
    }
}
