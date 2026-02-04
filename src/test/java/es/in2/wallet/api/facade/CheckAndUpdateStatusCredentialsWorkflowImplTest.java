package es.in2.wallet.api.facade;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.workflows.issuance.impl.CheckAndUpdateStatusCredentialsWorkflowImpl;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationConstants.PLAIN_LIST_ENTITY;
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

    private static WebClient webClientReturningJson(HttpStatus status, String jsonBody) {
        ClientResponse clientResponse = mock(ClientResponse.class);

        when(clientResponse.statusCode()).thenReturn(status);
        when(clientResponse.bodyToMono(String.class)).thenReturn(Mono.just(jsonBody));
        when(clientResponse.releaseBody()).thenReturn(Mono.empty());

        ExchangeFunction exchangeFunction = request -> Mono.just(clientResponse);

        return WebClient.builder()
                .exchangeFunction(exchangeFunction)
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

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId)).verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), eq(LifeCycleStatus.EXPIRED));
    }


    @Test
    void shouldMarkCredentialAsRevoked() {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().plusSeconds(3600).toString());

        String statusListCredentialUrl = "https://issuer.test/status";
        String statusListIndex = "abc123";

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential(statusListCredentialUrl)
                .statusListIndex(statusListIndex)
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        // The workflow reads CredentialStatusResponse[] and maps CredentialStatusResponse::credentialNonce
        WebClient fake = webClientReturningJson(HttpStatus.OK, "[{\"nonce\":\"abc123\"}]");
        when(webClient.centralizedWebClient()).thenReturn(fake);

        when(credentialService.updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED))
                .thenReturn(Mono.just(credential));

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(credentialService).updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED);
    }

    @Test
    void shouldMarkCredentialAsRevokedForUser() {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().plusSeconds(3600).toString());

        String statusListCredentialUrl = "https://issuer.test/status";

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential(statusListCredentialUrl)
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentialsByUser("test")).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        WebClient fake = webClientReturningJson(HttpStatus.OK, "[{\"nonce\":\"abc123\"}]");

        when(webClient.centralizedWebClient()).thenReturn(fake);

        when(credentialService.updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED))
                .thenReturn(Mono.just(credential));

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.executeForUser(processId, "test"))
                .verifyComplete();

        verify(credentialService).updateCredentialEntityLifeCycleStatus(credential, LifeCycleStatus.REVOKED);
    }

    @Test
    void shouldNotUpdateIfCredentialNotRevoked() {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().plusSeconds(3600).toString());

        String statusListCredentialUrl = "https://issuer.test/status";

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential(statusListCredentialUrl)
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentialsByUser("test")).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        // Different nonce => not revoked
        WebClient fake = webClientReturningJson(HttpStatus.OK, "[{\"nonce\":\"other-nonce\"}]");

        when(webClient.centralizedWebClient()).thenReturn(fake);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.executeForUser("process-id", "test"))
                .verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

    @Test
    void shouldIgnoreCredentialWithoutCredentialStatus() {
        Credential credential = buildCredential("VALID", "{}");

        ObjectNode vcJson = objectMapper.createObjectNode();
        vcJson.put("validUntil", Instant.now().plusSeconds(3600).toString());

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialJsonVc(credential)).thenReturn(vcJson);
        when(credentialService.getCredentialStatus(credential)).thenReturn(null);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute("process-id"))
                .verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

    @Test
    void shouldNotCallIssuerNorUpdateWhenCredentialIsNotValid() {
        Credential credential = buildCredential("REVOKED", "{}");

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(credentialService, never()).getCredentialJsonVc(any());
        verify(credentialService, never()).getCredentialStatus(any());
        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
        verify(webClient, never()).centralizedWebClient();
    }

    @Test
    void shouldIgnoreCredentialWhenStatusListCredentialIsNotHttps() {
        Credential credential = buildCredential("VALID", "{}");

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential("http://issuer.test/status")
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(webClient, never()).centralizedWebClient();
        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

    @Test
    void shouldIgnoreCredentialWhenStatusListCredentialIsInvalidUri() {
        Credential credential = buildCredential("VALID", "{}");

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential("ht!tp://bad url")
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(webClient, never()).centralizedWebClient();
        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

    @Test
    void shouldNotUpdateWhenIssuerReturnsHttpError() {
        Credential credential = buildCredential("VALID", "{}");

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential("https://issuer.test/status")
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        WebClient fake = webClientReturningJson(HttpStatus.INTERNAL_SERVER_ERROR, "boom");
        when(webClient.centralizedWebClient()).thenReturn(fake);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

    @Test
    void shouldNotUpdateWhenIssuerReturnsMalformedJson() {
        Credential credential = buildCredential("VALID", "{}");

        CredentialStatus status = CredentialStatus.builder()
                .statusListCredential("https://issuer.test/status")
                .statusListIndex("abc123")
                .type(PLAIN_LIST_ENTITY)
                .build();

        when(credentialService.getAllCredentials()).thenReturn(Mono.just(List.of(credential)));
        when(credentialService.getCredentialStatus(credential)).thenReturn(status);

        // Malformed JSON => ObjectMapper.readValue throws => workflow swallows error and completes
        WebClient fake = webClientReturningJson(HttpStatus.OK, "[{]");
        when(webClient.centralizedWebClient()).thenReturn(fake);

        StepVerifier.create(checkAndUpdateStatusCredentialsWorkflow.execute(processId))
                .verifyComplete();

        verify(credentialService, never()).updateCredentialEntityLifeCycleStatus(any(), any());
    }

}

