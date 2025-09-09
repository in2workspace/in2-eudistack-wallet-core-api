package es.in2.wallet.infrastructure.services;

import es.in2.wallet.domain.entities.DeferredCredentialMetadata;
import es.in2.wallet.domain.exceptions.NoSuchDeferredCredentialMetadataException;
import es.in2.wallet.domain.repositories.DeferredCredentialMetadataRepository;
import es.in2.wallet.domain.services.impl.DeferredCredentialMetadataServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialMetadataServiceImplTest {

    @Mock
    private DeferredCredentialMetadataRepository deferredCredentialMetadataRepository;

    @InjectMocks
    private DeferredCredentialMetadataServiceImpl service;

    @Test
    void testSaveDeferredCredentialMetadata_Success() {
        // GIVEN
        String processId = "procSave";
        String credentialId = UUID.randomUUID().toString();
        String transactionId = UUID.randomUUID().toString();
        String accessToken = "some-token";
        String deferredEndpoint = "https://example.com/deferred";
        Instant now = Instant.now();

        // We'll capture exactly what is passed to the repository
        ArgumentCaptor<DeferredCredentialMetadata> captor =
                ArgumentCaptor.forClass(DeferredCredentialMetadata.class);

        DeferredCredentialMetadata savedMetadata = DeferredCredentialMetadata.builder()
                .credentialId(credentialId)
                .transactionId(UUID.fromString(transactionId))
                .accessToken(accessToken)
                .deferredEndpoint(deferredEndpoint)
                .createdAt(now)
                .updatedAt(now)
                .build();

        when(deferredCredentialMetadataRepository.save(captor.capture()))
                .thenReturn(Mono.just(savedMetadata));

        // WHEN
        Mono<String> result = service.saveDeferredCredentialMetadata(
                processId,
                credentialId,
                transactionId,
                accessToken,
                deferredEndpoint
        );

        // THEN
        StepVerifier.create(result)
                .expectNext(credentialId)
                .verifyComplete();

        verify(deferredCredentialMetadataRepository)
                .save(argThat(md ->
                        md.getCredentialId().equals(credentialId)
                                && md.getTransactionId().toString().equals(transactionId)
                                && md.getAccessToken().equals(accessToken)
                                && md.getDeferredEndpoint().equals(deferredEndpoint)
                ));
    }

    @Test
    void testGetDeferredCredentialMetadataByCredentialId_Success() {
        // GIVEN
        String processId = "procGet";
        String credentialIdStr = UUID.randomUUID().toString();

        DeferredCredentialMetadata metadata = DeferredCredentialMetadata.builder()
                .credentialId(credentialIdStr)
                .transactionId(UUID.randomUUID())
                .accessToken("token")
                .deferredEndpoint("https://example.com/deferred")
                .build();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.just(metadata));

        // WHEN
        Mono<DeferredCredentialMetadata> result =
                service.getDeferredCredentialMetadataByCredentialId(processId, credentialIdStr);

        // THEN
        StepVerifier.create(result)
                .expectNext(metadata)
                .verifyComplete();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
    }

    @Test
    void testGetDeferredCredentialMetadataByCredentialId_NotFound() {
        // GIVEN
        String processId = "procGetNotFound";
        String credentialIdStr = UUID.randomUUID().toString();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.empty());

        // WHEN
        Mono<DeferredCredentialMetadata> result =
                service.getDeferredCredentialMetadataByCredentialId(processId, credentialIdStr);

        // THEN
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof NoSuchDeferredCredentialMetadataException
                        && ex.getMessage().contains("No deferred credential metadata found"))
                .verify();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
    }

    @Test
    void testDeleteDeferredCredentialMetadataByCredentialId_Success() {
        // GIVEN
        String processId = "procDel";
        String credentialIdStr = UUID.randomUUID().toString();

        DeferredCredentialMetadata metadata = DeferredCredentialMetadata.builder()
                .credentialId(credentialIdStr)
                .transactionId(UUID.randomUUID())
                .build();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.just(metadata));
        when(deferredCredentialMetadataRepository.delete(metadata))
                .thenReturn(Mono.empty());

        // WHEN
        Mono<Void> result = service.deleteDeferredCredentialMetadataByCredentialId(processId, credentialIdStr);

        // THEN
        StepVerifier.create(result)
                .verifyComplete();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
        verify(deferredCredentialMetadataRepository).delete(metadata);
    }

    @Test
    void testDeleteDeferredCredentialMetadataByCredentialId_NotFound() {
        // GIVEN
        String processId = "procDelNotFound";
        String credentialIdStr = UUID.randomUUID().toString();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.empty());

        // WHEN
        Mono<Void> result = service.deleteDeferredCredentialMetadataByCredentialId(processId, credentialIdStr);

        // THEN
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof NoSuchDeferredCredentialMetadataException
                        && ex.getMessage().contains("No deferred credential metadata found"))
                .verify();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
        verify(deferredCredentialMetadataRepository, never()).delete(any());
    }

    @Test
    void testUpdateDeferredCredentialMetadataTransactionIdByCredentialId_Success() {
        // GIVEN
        String processId = "procUpdate";
        String credentialIdStr = UUID.randomUUID().toString();
        String newTransactionIdStr = UUID.randomUUID().toString();

        DeferredCredentialMetadata existing = DeferredCredentialMetadata.builder()
                .credentialId(credentialIdStr)
                .transactionId(UUID.randomUUID())
                .build();

        // We'll capture what gets saved
        ArgumentCaptor<DeferredCredentialMetadata> captor =
                ArgumentCaptor.forClass(DeferredCredentialMetadata.class);

        // Manually build the "updated" metadata
        DeferredCredentialMetadata updated = DeferredCredentialMetadata.builder()
                .credentialId(credentialIdStr)
                .transactionId(UUID.fromString(newTransactionIdStr))
                .updatedAt(Instant.now())
                .build();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.just(existing));
        when(deferredCredentialMetadataRepository.save(captor.capture()))
                .thenReturn(Mono.just(updated));

        // WHEN
        Mono<Void> result = service.updateDeferredCredentialMetadataTransactionIdByCredentialId(
                processId,
                credentialIdStr,
                newTransactionIdStr
        );

        // THEN
        StepVerifier.create(result)
                .verifyComplete();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
        verify(deferredCredentialMetadataRepository).save(argThat(md ->
                md.getTransactionId().toString().equals(newTransactionIdStr)
        ));

        DeferredCredentialMetadata passedToSave = captor.getValue();
        assertEquals(credentialIdStr, passedToSave.getCredentialId());
        assertEquals(UUID.fromString(newTransactionIdStr), passedToSave.getTransactionId());
    }

    @Test
    void testUpdateDeferredCredentialMetadataTransactionIdByCredentialId_NotFound() {
        // GIVEN
        String processId = "procUpdateNotFound";
        String credentialIdStr = UUID.randomUUID().toString();
        String newTransactionIdStr = UUID.randomUUID().toString();

        when(deferredCredentialMetadataRepository.findByCredentialId(credentialIdStr))
                .thenReturn(Mono.empty());

        // WHEN
        Mono<Void> result = service.updateDeferredCredentialMetadataTransactionIdByCredentialId(
                processId, credentialIdStr, newTransactionIdStr
        );

        // THEN
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof NoSuchDeferredCredentialMetadataException
                        && ex.getMessage().contains("No deferred credential metadata found"))
                .verify();

        verify(deferredCredentialMetadataRepository).findByCredentialId(credentialIdStr);
        verify(deferredCredentialMetadataRepository, never()).save(any());
    }
}