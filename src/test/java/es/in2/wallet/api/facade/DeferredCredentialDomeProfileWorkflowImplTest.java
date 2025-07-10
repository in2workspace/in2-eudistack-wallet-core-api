package es.in2.wallet.api.facade;

import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.dto.CredentialResponseWithStatus;
import es.in2.wallet.application.workflows.issuance.impl.DeferredCredentialDomeProfileWorkflowImpl;
import es.in2.wallet.domain.entities.DeferredCredentialMetadata;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.domain.services.DeferredCredentialMetadataService;
import es.in2.wallet.domain.services.OID4VCICredentialService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialDomeProfileWorkflowImplTest {

    @Mock
    private OID4VCICredentialService oid4vciCredentialService;
    @Mock
    private CredentialService credentialService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @InjectMocks
    private DeferredCredentialDomeProfileWorkflowImpl service;

    @Test
    void requestDeferredCredential_withNewCredential_Success(){
        String processId = "processId";
        String userId = UUID.randomUUID().toString();
        String credentialId = UUID.randomUUID().toString();
        UUID transactionUuid = UUID.randomUUID();
        String accessToken = "access123";
        String deferredEndpoint = "https://example.com/callback";

        DeferredCredentialMetadata deferredCredentialMetadata = DeferredCredentialMetadata.builder()
                .credentialId(credentialId)
                .transactionId(transactionUuid)
                .accessToken(accessToken)
                .deferredEndpoint(deferredEndpoint)
                .build();

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("ey134...")
        );

        CredentialResponse credentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder()
                .credentialResponse(credentialResponse)
                .build();

        when(deferredCredentialMetadataService.getDeferredCredentialMetadataByCredentialId(processId, credentialId))
                .thenReturn(Mono.just(deferredCredentialMetadata));

        when(oid4vciCredentialService.getCredentialDomeDeferredCase(transactionUuid.toString(),accessToken,deferredEndpoint)).thenReturn(Mono.just(credentialResponseWithStatus));

        when(credentialService.saveDeferredCredential(processId, userId, credentialId, credentialResponse))
                .thenReturn(Mono.empty());

        when(deferredCredentialMetadataService.deleteDeferredCredentialMetadataByCredentialId(processId, credentialId))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.requestDeferredCredential(processId, userId, credentialId))
                .verifyComplete();
    }

    @Test
    void requestDeferredCredential_withNewTransactionId_Success(){
        String processId = "processId";
        String userId = UUID.randomUUID().toString();
        String credentialId = UUID.randomUUID().toString();
        UUID transactionUuid = UUID.randomUUID();
        String newTransactionUuid = UUID.randomUUID().toString();
        String accessToken = "access123";
        String deferredEndpoint = "https://example.com/callback";

        DeferredCredentialMetadata deferredCredentialMetadata = DeferredCredentialMetadata.builder()
                .credentialId(credentialId)
                .transactionId(transactionUuid)
                .accessToken(accessToken)
                .deferredEndpoint(deferredEndpoint)
                .build();

        CredentialResponse credentialResponse = CredentialResponse.builder()
                .transactionId(newTransactionUuid)
                .build();

        CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder()
                .credentialResponse(credentialResponse)
                .build();

        when(deferredCredentialMetadataService.getDeferredCredentialMetadataByCredentialId(processId, credentialId))
                .thenReturn(Mono.just(deferredCredentialMetadata));

        when(oid4vciCredentialService.getCredentialDomeDeferredCase(transactionUuid.toString(),accessToken,deferredEndpoint)).thenReturn(Mono.just(credentialResponseWithStatus));

        when(deferredCredentialMetadataService.updateDeferredCredentialMetadataTransactionIdByCredentialId(processId, credentialId, newTransactionUuid))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.requestDeferredCredential(processId, userId, credentialId))
                .verifyComplete();
    }
}

