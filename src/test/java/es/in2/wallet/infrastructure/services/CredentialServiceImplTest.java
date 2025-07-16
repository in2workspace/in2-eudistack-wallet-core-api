package es.in2.wallet.infrastructure.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.CredentialFormats;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.exceptions.NoSuchVerifiableCredentialException;
import es.in2.wallet.domain.repositories.CredentialRepository;
import es.in2.wallet.domain.services.impl.CredentialServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialServiceImplTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private CredentialServiceImpl credentialRepositoryService;

    @Test
    void testSaveCredential_PlainJsonFormat_Success() throws JsonProcessingException {
        // GIVEN
        String processId = "proc123";
        UUID userId = UUID.randomUUID();
        String credential = "credential";
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials(credential)
        );
        String credentialId = "8c7a6213-544d-450d-8e3d-b41fa9009198";
        CredentialResponse response = CredentialResponse.builder()
                .transactionId("tx123")
                .credentials(credentialList)
                .build();
        String format = "jwt_vc";

        // Suppose the repository will return a saved credential with a known ID
        Credential savedEntity = Credential.builder()
                .id(UUID.fromString(credentialId))
                .userId(userId)
                .build();

        // We'll capture the credential passed into save(...)
        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        when(credentialRepository.save(captor.capture()))
                .thenReturn(Mono.just(savedEntity));

        when(objectMapper.readTree(credential)).thenReturn(getJsonNodeCredentialLearCredentialEmployee());

        // WHEN
        Mono<String> result = credentialRepositoryService.saveCredential(processId, userId, response, format);

        // THEN
        StepVerifier.create(result)
                .expectNext(credentialId)
                .verifyComplete();

        // Verify the repository was called exactly once
        verify(credentialRepository).save(any(Credential.class));

        // Check the captured entity's fields
        Credential passedToSave = captor.getValue();
        assertEquals(userId, passedToSave.getUserId());
        assertEquals(LifeCycleStatus.ISSUED.toString(), passedToSave.getCredentialStatus());
        assertNull(passedToSave.getCredentialData());
        // plus any other checks you wish to make
    }

    @Test
    void testSaveCredential_JwtFormat_Success() throws Exception {
        // GIVEN
        String processId = "proc123";
        UUID userId = UUID.randomUUID();
        String credential = "someJwtData";
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials(credential)
        );
        String format = "jwt_vc";
        // This is the 'CredentialResponse' with format=JWT_VC
        CredentialResponse response = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        String credentialId = "8c7a6213-544d-450d-8e3d-b41fa9009198";

        // Suppose the repository will return a saved credential with a known ID
        Credential savedEntity = Credential.builder()
                .id(UUID.fromString(credentialId))
                .userId(userId)
                .build();

        // We'll capture the 'Credential' passed into 'save(...)'
        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        when(credentialRepository.save(captor.capture()))
                .thenReturn(Mono.just(savedEntity));

        SignedJWT mockJwt = mock(SignedJWT.class);

        // We'll define a payload that has "vc"
        String fakePayloadJson = """
        {
          "vc": {
            "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
            "type": ["VerifiableCredential", "LEARCredentialEmployee"]
          }
        }
        """;
        // Next, we create a 'Payload' object from the Nimbus library
        Payload mockPayload = new Payload(fakePayloadJson);

        // Make the SignedJWT return that payload
        when(mockJwt.getPayload()).thenReturn(mockPayload);

        // Use a static mock to intercept SignedJWT.parse(...)
        try (MockedStatic<SignedJWT> staticMock = Mockito.mockStatic(SignedJWT.class)) {
            // When someone calls SignedJWT.parse("someJwtData"), return mockJwt
            staticMock.when(() -> SignedJWT.parse(credential))
                    .thenReturn(mockJwt);

            // 2) We also need to mock objectMapper.readTree(...) so that it returns a root JsonNode
            //    representing fakePayloadJson
            JsonNode rootNode = new ObjectMapper().readTree(fakePayloadJson);
            when(objectMapper.readTree(fakePayloadJson)).thenReturn(rootNode);

            // WHEN
            Mono<String> result = credentialRepositoryService.saveCredential(processId, userId, response, format);

            // THEN
            StepVerifier.create(result)
                    .expectNext(credentialId)
                    .verifyComplete();

            verify(credentialRepository).save(any(Credential.class));

            Credential passedToSave = captor.getValue();
            assertEquals(LifeCycleStatus.VALID.toString(), passedToSave.getCredentialStatus());
            assertEquals(userId, passedToSave.getUserId());
            assertEquals(CredentialFormats.JWT_VC.toString(), passedToSave.getCredentialFormat());
            assertEquals(credential, passedToSave.getCredentialData());
        }
    }


    @Test
    void testSaveCredential_UnsupportedFormat_Error() {
        // GIVEN
        String processId = "proc123";
        UUID userId = UUID.randomUUID();
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("foo-data")
        );
        CredentialResponse response = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        // WHEN
        Mono<String> result = credentialRepositoryService.saveCredential(processId, userId, response, "FOO_FORMAT");

        // THEN
        StepVerifier.create(result)
                .expectErrorMatches(ex -> ex instanceof IllegalArgumentException
                        && ex.getMessage().contains("Unsupported credential format"))
                .verify();

        verify(credentialRepository, never()).save(any(Credential.class));
    }

    @Test
    void testSaveDeferredCredential_Success() {
        // We test a credential that is currently ISSUED => we can update to VALID
        String processId = "procXYZ";
        UUID userId = UUID.randomUUID();
        UUID uuid = UUID.randomUUID();
        String cred = UUID.randomUUID().toString();

        // The existing credential
        Credential existing = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userId)
                .credentialStatus(LifeCycleStatus.ISSUED.toString())
                .build();

        when(credentialRepository.findByCredentialId(cred)).thenReturn(Mono.just(existing));

        // Suppose once we update the credential, we store it as VALID
        Credential updated = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userId)
                .credentialStatus(LifeCycleStatus.VALID.toString())
                .build();

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        when(credentialRepository.save(captor.capture())).thenReturn(Mono.just(updated));
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("some-jwt-data")
        );
        CredentialResponse deferredResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        Mono<Void> result = credentialRepositoryService.saveDeferredCredential(
                processId,
                userId.toString(),
                cred,
                deferredResponse
        );

        StepVerifier.create(result).verifyComplete();

        verify(credentialRepository).save(any(Credential.class));

        // Check that the repository saved with status = VALID
        Credential passedToSave = captor.getValue();
        assertEquals(LifeCycleStatus.VALID.toString(), passedToSave.getCredentialStatus());
        assertEquals("some-jwt-data", passedToSave.getCredentialData());
    }

    @Test
    void testExtractDidFromCredential_BasicType() throws JsonProcessingException {
        String processId = "procDid";
        UUID userUuid = UUID.randomUUID();
        UUID uuid = UUID.randomUUID();
        String cred = UUID.randomUUID().toString();
        String credential = "credential";

        // The credential has no LEARCredentialEmployee => DID is at /credentialSubject/id
        Credential existing = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userUuid)
                .credentialType(List.of("VerifiableCredential", "AnotherType"))
                .jsonVc(credential)
                .build();

        when(credentialRepository.findByCredentialId(cred))
                .thenReturn(Mono.just(existing));

        when(objectMapper.readTree(credential)).thenReturn(getJsonNodeCredential());

        Mono<String> result =
                credentialRepositoryService.extractDidFromCredential(processId,
                        cred,
                        userUuid.toString()
                );

        StepVerifier.create(result)
                .expectNext("did:example:basic")
                .verifyComplete();
    }

    @Test
    void testExtractDidFromCredential_LearType() throws JsonProcessingException {
        String processId = "procDid";
        UUID userUuid = UUID.randomUUID();
        UUID uuid = UUID.randomUUID();
        String cred = UUID.randomUUID().toString();
        String credential = "credential";

        // The credential has type "LEARCredentialEmployee", so DID is at /credentialSubject/mandate/mandatee/id
        Credential existing = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userUuid)
                .credentialType(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .jsonVc(credential)
                .build();

        when(credentialRepository.findByCredentialId(cred)).thenReturn(Mono.just(existing));
        when(objectMapper.readTree(credential)).thenReturn(getJsonNodeCredentialLearCredentialEmployee());

        Mono<String> result =
                credentialRepositoryService.extractDidFromCredential(processId,
                        cred,
                        userUuid.toString()
                );

        StepVerifier.create(result)
                .expectNext("did:example:987")
                .verifyComplete();
    }

    @Test
    void testGetCredentialsByUserId_Success() throws JsonProcessingException {
        String processId = "procABC";
        UUID userUuid = UUID.randomUUID();
        String credentialId1 = UUID.randomUUID().toString();
        String credentialId2 = UUID.randomUUID().toString();
        String credential1 = "credential1";
        String credential2 = "credential2";

        // Suppose the repository returns 2 credentials for the user
        Credential c1 = Credential.builder()
                .id(UUID.randomUUID())
                .credentialId(credentialId1)
                .userId(userUuid)
                .credentialType(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                .credentialStatus(LifeCycleStatus.VALID.toString())
                .jsonVc(credential1)
                .build();
        Credential c2 = Credential.builder()
                .id(UUID.randomUUID())
                .credentialId(credentialId2)
                .userId(userUuid)
                .credentialType(List.of("VerifiableCredential", "AnotherType"))
                .credentialStatus(LifeCycleStatus.ISSUED.toString())
                .jsonVc(credential2)
                .build();

        when(objectMapper.readTree(credential1)).thenReturn(getJsonNodeCredentialLearCredentialEmployee());
        when(objectMapper.readTree(credential2)).thenReturn(getJsonNodeCredential());

        when(credentialRepository.findAllByUserId(userUuid))
                .thenReturn(Flux.just(c1, c2));

        Mono<List<VerifiableCredential>> result =
                credentialRepositoryService.getCredentialsByUserId(processId, userUuid.toString());

        StepVerifier.create(result)
                .assertNext(list -> assertEquals(1, list.size()))
                .verifyComplete();
    }

    @Test
    void testGetCredentialsByUserId_NoCredentialsFound_ShouldReturnError() {
        String processId = "procXYZ";
        UUID userUuid = UUID.randomUUID();

        when(credentialRepository.findAllByUserId(userUuid))
                .thenReturn(Flux.empty());

        Mono<List<VerifiableCredential>> result =
                credentialRepositoryService.getCredentialsByUserId(processId, userUuid.toString());

        StepVerifier.create(result)
                .expectError(NoSuchVerifiableCredentialException.class)
                .verify();
    }

    @Test
    void testGetCredentialsByUserId_ReadTreeFails_ShouldSkipCredential() throws Exception {
        String processId = "procXYZ";
        UUID userUuid = UUID.randomUUID();
        String credentialId1 = UUID.randomUUID().toString();
        String badCredentialJson = "invalid-json";

        Credential badCredential = Credential.builder()
                .id(UUID.randomUUID())
                .credentialId(credentialId1)
                .userId(userUuid)
                .credentialType(List.of("VerifiableCredential"))
                .credentialStatus(LifeCycleStatus.VALID.toString())
                .jsonVc(badCredentialJson)
                .build();
        when(objectMapper.readTree(badCredentialJson)).thenThrow(new JsonProcessingException("bad json") {});

        when(credentialRepository.findAllByUserId(userUuid))
                .thenReturn(Flux.just(badCredential));

        Mono<List<VerifiableCredential>> result =
                credentialRepositoryService.getCredentialsByUserId(processId, userUuid.toString());

        StepVerifier.create(result)
                .expectError(NoSuchVerifiableCredentialException.class)
                .verify();
    }




    @Test
    void testGetCredentialDataByIdAndUserId_Success() {
        String processId = "procDEF";
        UUID userUuid = UUID.randomUUID();
        UUID uuid = UUID.randomUUID();
        String cred = UUID.randomUUID().toString();

        Credential existing = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userUuid)
                .credentialData("some-raw-data-here")
                .build();

        when(credentialRepository.findByCredentialId(cred)).thenReturn(Mono.just(existing));

        Mono<String> result = credentialRepositoryService.getCredentialDataByIdAndUserId(
                processId,
                userUuid.toString(),
                cred
        );

        StepVerifier.create(result)
                .expectNext("some-raw-data-here")
                .verifyComplete();
    }

    @Test
    void testDeleteCredential_Success() {
        String processId = "procDel";
        UUID userUuid = UUID.randomUUID();
        UUID uuid = UUID.randomUUID();
        String cred = UUID.randomUUID().toString();

        Credential existing = Credential.builder()
                .id(uuid)
                .credentialId(cred)
                .userId(userUuid)
                .build();

        when(credentialRepository.findByCredentialId(cred))
                .thenReturn(Mono.just(existing));
        when(credentialRepository.delete(existing))
                .thenReturn(Mono.empty());

        Mono<Void> result = credentialRepositoryService.deleteCredential(
                processId,
                cred,
                userUuid.toString()
        );

        StepVerifier.create(result).verifyComplete();

        verify(credentialRepository).delete(existing);
    }

    @Test
    void testGetCredentialsByUserIdTypeAndFormat_success() throws JsonProcessingException {
        String processId = "proc123";
        UUID userUuid = UUID.randomUUID();
        String userId = userUuid.toString();
        String requiredType = "LEARCredentialEmployee";
        String format = "JWT_VC";

        String credentialId = UUID.randomUUID().toString();
        String jsonVc = """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/extra"],
              "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "issuer": {
                "id": "did:example:issuer"
              },
              "validUntil": "2026-12-31T23:59:59Z",
              "validFrom": "2023-01-01T00:00:00Z",
              "credentialSubject": {
                "name": "Credential Name",
                "description": "Credential Description",
                "mandate": {
                  "mandatee": {
                    "id": "did:example:987"
                  }
                }
              },
              "credentialStatus": {
                "id": "https://example.com/status/1234",
                "type": "StatusList2021Entry",
                "statusPurpose": "revocation",
                "statusListIndex": "ZpKxfjwWSZifwCihxFoUxQ",
                "statusListCredential": "https://example.com/status/1234"
              }
            }
            """;

        Credential credential = Credential.builder()
                .credentialId(credentialId)
                .userId(userUuid)
                .credentialFormat(format)
                .credentialType(List.of("VerifiableCredential", requiredType))
                .credentialStatus(LifeCycleStatus.VALID.toString())
                .jsonVc(jsonVc)
                .build();

        when(credentialRepository.findAllByUserId(userUuid))
                .thenReturn(Flux.just(credential));
        when(objectMapper.readTree(jsonVc)).thenReturn(getJsonNodeCredentialLearCredentialEmployee());

        Mono<List<VerifiableCredential>> result = credentialRepositoryService
                .getCredentialsByUserIdAndType(processId, userId, requiredType);

        StepVerifier.create(result)
                .assertNext(list -> assertEquals(1, list.size()))
                .verifyComplete();
    }

    @Test
    void testGetCredentialsByUserIdTypeAndFormat_shouldThrowWhenNoMatchingCredentials() {
        // GIVEN
        String processId = "proc123";
        UUID userUuid = UUID.randomUUID();
        String credentialId = UUID.randomUUID().toString();
        String userId = userUuid.toString();
        String requiredType = "LEARCredentialEmployee";

        Credential credential = Credential.builder()
                .credentialId(credentialId)
                .userId(userUuid)
                .credentialFormat("ldp_vc")
                .credentialType(List.of("VerifiableCredential", "SomeOtherType"))
                .credentialStatus(LifeCycleStatus.VALID.toString())
                .jsonVc("{}")
                .build();

        when(credentialRepository.findAllByUserId(userUuid))
                .thenReturn(Flux.just(credential));

        // WHEN
        Mono<List<VerifiableCredential>> result = credentialRepositoryService
                .getCredentialsByUserIdAndType(processId, userId, requiredType);

        // THEN
        StepVerifier.create(result)
                .expectErrorMatches(ex ->
                        ex instanceof NoSuchVerifiableCredentialException &&
                                ex.getMessage().equals("No credentials found for userId=" + userId +
                                        " with type=" + requiredType +
                                        " in JWT_VC format."))
                .verify();
    }

    private JsonNode getJsonNodeCredentialLearCredentialEmployee() throws JsonProcessingException {
        String json = """
            {
              "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/extra"],
              "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "issuer": {
                "id": "did:example:issuer"
              },
              "validUntil": "2026-12-31T23:59:59Z",
              "validFrom": "2023-01-01T00:00:00Z",
              "credentialSubject": {
                "name": "Credential Name",
                "description": "Credential Description",
                "mandate": {
                  "mandatee": {
                    "id": "did:example:987"
                  }
                }
              },
              "credentialStatus": {
                "id": "https://example.com/status/1234",
                "type": "StatusList2021Entry"
              }
            }
            """;
        ObjectMapper objectMapper2 = new ObjectMapper();
        return objectMapper2.readTree(json);
    }

    private JsonNode getJsonNodeCredentialLearCredentialEmployee2() throws JsonProcessingException {
        String json = """
            {
              "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "issuer": {
                "id": "did:example:issuer"
              },
              "validUntil": "2026-12-31T23:59:59Z",
              "validFrom": "2023-01-01T00:00:00Z",
              "credentialSubject": {
                "name": "Credential Name",
                "description": "Credential Description",
                "mandate": {
                  "mandatee": {
                    "id": "did:example:987"
                  }
                }
              },
              "credentialStatus": {
                "id": "https://example.com/status/1234",
                "type": "StatusList2021Entry"
              }
            }
            """;
        ObjectMapper objectMapper2 = new ObjectMapper();
        return objectMapper2.readTree(json);
    }

    private JsonNode getJsonNodeCredential() throws JsonProcessingException {
        String json = """
                {
                    "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
                    "type": [
                        "VerifiableCredential",
                        "AnotherType"
                    ],
                    "credentialSubject" : {
                        "id" : "did:example:basic"
                    },
                    "validUntil": "2026-12-31T23:59:59Z"
                }
                """;
        ObjectMapper objectMapper2 = new ObjectMapper();
        return objectMapper2.readTree(json);
    }
}


