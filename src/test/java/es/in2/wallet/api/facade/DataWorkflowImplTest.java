package es.in2.wallet.api.facade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.ports.VaultService;
import es.in2.wallet.application.workflows.data.impl.DataWorkflowImpl;
import es.in2.wallet.domain.services.CredentialService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.ZonedDateTime;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DataWorkflowImplTest {

    @Mock
    private CredentialService credentialService;

    @Mock
    private VaultService vaultService;

    @InjectMocks
    private DataWorkflowImpl userDataFacadeService;

    @Test
    void getUserVCs_UserExists_ReturnsVCs() throws JsonProcessingException {
        String processId = "process1";
        String userId = "user1";

        String jsonSubject = """
                    {
                        "credentialSubject": {
                            "id": "did:example:123"
                        }
                    }
                """;
        ObjectMapper objectMapper2 = new ObjectMapper();
        JsonNode credentialSubject = objectMapper2.readTree(jsonSubject);

        String jsonIssuer = """
        "issuer": {
            "id"          : "did:elsi:VATES-A12345678"                                ,
            "organization": "TRUST SERVICES, S.L."                                    ,
            "country"     : "ES"                                                      ,
            "commonName"  : "TRUST SERVICE ELECTRONIC SEAL FOR VERIFIABLE CREDENTIALS",
            "serialNumber": "610dde5a0000000003"
          }
        """;

        ObjectMapper objectMapper3 = new ObjectMapper();
        JsonNode issuer = objectMapper3.readTree(jsonIssuer);

        String jsonStatus = """
        {
            "id": "https://issuer.dome-marketplace.eu/credentials/status/1#urn:uuid:8c7a6213-544d-450d-8e3d-b41fa9009198",
            "type": "PlainListEntity",
            "statusPurpose": "revocation",
            "statusListIndex": "urn:uuid:8c7a6213-544d-450d-8e3d-b41fa9009198",
            "statusListCredential": "https://issuer.dome-marketplace.eu/credentials/status/1"
          }
        """;
        ObjectMapper objectMapper4 = new ObjectMapper();
        JsonNode credentialStatusNode = objectMapper4.readTree(jsonStatus);
        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id(credentialStatusNode.get("id").asText())
                .type(credentialStatusNode.get("type").asText())
                .statusPurpose(credentialStatusNode.get("statusPurpose").asText())
                .statusListIndex(credentialStatusNode.get("statusListIndex").asText())
                .statusListCredential(credentialStatusNode.get("statusListCredential").asText())
                .build();

        List<VerifiableCredential> expectedCredentials = List.of(new VerifiableCredential(List.of("context"),"id1", List.of("type"), "VALID", "name", "desc", issuer, ZonedDateTime.now().toString(), ZonedDateTime.now().toString(), credentialSubject, credentialStatus, "ofdasjfsdojgofdjgodfjgoodjgojgo"));

        when(credentialService.getCredentialsByUserId(processId, userId)).thenReturn(Mono.just(expectedCredentials));

        StepVerifier.create(userDataFacadeService.getAllCredentialsByUserId(processId, userId))
                .expectNext(expectedCredentials)
                .verifyComplete();
        verify(credentialService).getCredentialsByUserId(processId, userId);
    }

    @Test
    void getUserVCs_WhenCredentialServiceFails_ShouldReturnError() {
        String processId = "process1";
        String userId = "user1";

        RuntimeException simulatedException = new RuntimeException("Database connection failed");

        when(credentialService.getCredentialsByUserId(processId, userId))
                .thenReturn(Mono.error(simulatedException));

        StepVerifier.create(userDataFacadeService.getAllCredentialsByUserId(processId, userId))
                .expectErrorMatches(throwable ->
                        throwable instanceof RuntimeException &&
                                throwable.getMessage().equals("Database connection failed")
                )
                .verify();

        verify(credentialService).getCredentialsByUserId(processId, userId);
    }



    @Test
    void deleteVerifiableCredentialById_CredentialExists_DeletesCredential() {
        String processId = "process1";
        String userId = "user1";
        String credentialId = "cred1";
        String did = "did:example:123";

        when(credentialService.extractDidFromCredential(processId, credentialId, userId)).thenReturn(Mono.just(did));
        when(vaultService.deleteSecretByKey(did)).thenReturn(Mono.empty());
        when(credentialService.deleteCredential(processId, credentialId, userId)).thenReturn(Mono.empty());

        StepVerifier.create(userDataFacadeService.deleteCredentialByIdAndUserId(processId, credentialId, userId))
                .verifyComplete();

        verify(credentialService).extractDidFromCredential(processId, credentialId, userId);
        verify(vaultService).deleteSecretByKey(did);
        verify(credentialService).deleteCredential(processId, credentialId, userId);
    }

}

