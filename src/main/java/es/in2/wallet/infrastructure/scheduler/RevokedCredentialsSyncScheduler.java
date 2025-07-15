package es.in2.wallet.infrastructure.scheduler;


import es.in2.wallet.infrastructure.scheduler.services.RevokedCredentialSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class RevokedCredentialsSyncScheduler {

    private final RevokedCredentialSyncService revokedCredentialSyncService;

    //@Scheduled(cron = "0 0 0 * * *", zone = "Europe/Madrid")
    @Scheduled(cron = "0 */2 * * * *", zone = "Europe/Madrid")
    public void syncRevokedCredentials() {
        log.debug("Syncing revoked credentials");
        String processId = UUID.randomUUID().toString();
        revokedCredentialSyncService.execute(processId);
    }
}
