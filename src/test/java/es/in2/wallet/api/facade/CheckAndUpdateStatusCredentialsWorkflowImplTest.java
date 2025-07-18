package es.in2.wallet.api.facade;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.workflows.issuance.impl.CheckAndUpdateStatusCredentialsWorkflowImpl;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CheckAndUpdateStatusCredentialsWorkflowImplTest {
    @Mock
    private CredentialService credentialService;
    @Spy
    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock
    private WebClientConfig webClient;
    @InjectMocks
    private CheckAndUpdateStatusCredentialsWorkflowImpl checkAndUpdateStatusCredentialsWorkflow;
    private final String processId = "process-test";
    private Credential buildCredential(String status, String jsonVc) {
        return Credential.builder()
                .credentialId(UUID.randomUUID().toString())
                .userId(UUID.randomUUID())
                .credentialFormat("ldp_vc")
                .credentialType(List.of("VerifiableCredential"))
                .credentialStatus(status)
                .jsonVc(jsonVc)
                .build();
    }

    @Test
    void shouldMarkCredentialAsExpired() {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().minusSeconds(3600).toString());

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.EXPIRED))
                .thenReturn(Mono.just(credential));

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(credentialService).updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.EXPIRED);
    }


    @Test
    void shouldNotUpdateIfAlreadyExpired() {
        Credential credential = buildCredential("EXPIRED", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().minusSeconds(3600).toString());

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId)).verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), eq(LifeCycleStatus.EXPIRED));
    }


    @Test
    void shouldMarkCredentialAsRevoked() throws IOException {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().plusSeconds(3600).toString());

        MockWebServer server = new MockWebServer();
        server.enqueue(new MockResponse()
                .setBody("[{\"credentialNonce\": \"abc123\"}]")
                .setHeader("Content-Type", "application/json")
                .setResponseCode(200));
        server.start();

        String statusListCredentialUrl = server.url("/status").toString();
        String statusListIndex = "abc123";

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential(statusListCredentialUrl)
                .statusListIndex(statusListIndex)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);
        when(webClient.centralizedWebClient()).thenReturn(WebClient.create());
        when(credentialService.updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED))
                .thenReturn(Mono.just(credential));

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute("test-process"))
                .verifyComplete();

        server.shutdown();

        verify(credentialService).updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED);
    }







}

