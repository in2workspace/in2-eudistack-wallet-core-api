package es.in2.wallet.infrastructure.scheduler;

import es.in2.wallet.application.workflows.issuance.CheckAndUpdateStatusCredentialsWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusCredentialsSyncSchedulerTest {
    @Mock
    private CheckAndUpdateStatusCredentialsWorkflow mockWorkflow;

    @InjectMocks
    private StatusCredentialsSyncScheduler scheduler;

    @Test
    void shouldInvokeWorkflowWhenSyncStatusCredentialsRuns() {
        when(mockWorkflow.execute(anyString())).thenReturn(Mono.empty());
        scheduler.syncStatusCredentials();
        verify(mockWorkflow, times(1)).execute(anyString());
    }

    @Test
    void shouldLogErrorWhenWorkflowFails() {
        when(mockWorkflow.execute(anyString())).thenReturn(Mono.error(new RuntimeException("Failed")));
        scheduler.syncStatusCredentials();
        verify(mockWorkflow).execute(anyString());
    }


}
