package es.in2.wallet.api.ebsi.comformance.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialsBasicInfo;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.ports.AppConfig;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.domain.services.DidKeyGeneratorService;
import es.in2.wallet.domain.services.UserService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import es.in2.wallet.infrastructure.ebsi.config.EbsiConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EbsiConfigTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private AppConfig appConfig;

    @Mock
    private DidKeyGeneratorService didKeyGeneratorService;

    @Mock
    private CredentialService credentialService;

    @Mock
    private UserService userService;

    @Mock
    private WebClientConfig webClientConfig;

    @InjectMocks
    private EbsiConfig ebsiConfig;

    @Test
    void testInitErrorDuringInitialization() {
        // GIVEN: identity provider returns 400, causing an error
        when(appConfig.getIdentityProviderClientSecret()).thenReturn("1234");
        when(appConfig.getIdentityProviderUsername()).thenReturn("user");
        when(appConfig.getIdentityProviderPassword()).thenReturn("4321");
        when(appConfig.getIdentityProviderClientId()).thenReturn("wallet");

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        // Mock a BAD_REQUEST response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.BAD_REQUEST)
                .header(CONTENT_TYPE, "application/json")
                .body("error")
                .build();

        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        // WHEN / THEN
        StepVerifier.create(ebsiConfig.init())
                .expectErrorMatches(ex -> ex instanceof RuntimeException &&
                        ex.getMessage().contains("Error retrieving token for user"))
                .verify();
    }

    @Test
    void testInitWhenDidWasAlreadyGenerated() throws JsonProcessingException {
        String userId = "e2a066f5-4c00-4956-b444-7ea5e156e05d";
        String expectedDid = "did:example:123";
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";

        when(appConfig.getIdentityProviderClientSecret()).thenReturn("1234");
        when(appConfig.getIdentityProviderUsername()).thenReturn("user");
        when(appConfig.getIdentityProviderPassword()).thenReturn("4321");
        when(appConfig.getIdentityProviderClientId()).thenReturn("wallet");

        // Mock successful token retrieval
        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, "application/json")
                .body("token")
                .build();
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        Map<String, Object> mapWithToken = Map.of("access_token", token);
        when(objectMapper.readValue(eq("token"), any(TypeReference.class)))
                .thenReturn(mapWithToken);

        // This scenario: We already have a credential => no new DID is generated
        // We mock 'getCredentialsByUserIdAndType' to return a list with one item
        VerifiableCredential existingCredInfo = VerifiableCredential.builder()
                .id("urn:entities:credential:exampleCredential-xyz")
                .build();
        when(credentialService.getCredentialsByUserIdAndType(anyString(), eq(userId), eq("ExampleCredential")))
                .thenReturn(Mono.just(List.of(existingCredInfo)));

        // So we extract the DID from that credential
        when(credentialService.extractDidFromCredential(anyString(), eq(existingCredInfo.id()), eq(userId)))
                .thenReturn(Mono.just(expectedDid));

        // WHEN / THEN
        StepVerifier.create(ebsiConfig.init())
                .expectNext(expectedDid)
                .verifyComplete();

    }

    @Test
    void testInitWhenDidWasNotGeneratedYet() throws JsonProcessingException {
        String userId = "e2a066f5-4c00-4956-b444-7ea5e156e05d";
        String expectedDid = "did:example:456";
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIyQ1ltNzdGdGdRNS1uU2stU3p4T2VYYUVOUTRoSGRkNkR5U2NYZzJFaXJjIn0.eyJleHAiOjE3MTAyNDM2MzIsImlhdCI6MTcxMDI0MzMzMiwiYXV0aF90aW1lIjoxNzEwMjQwMTczLCJqdGkiOiJmY2NhNzU5MS02NzQyLTRjMzAtOTQ5Yy1lZTk3MDcxOTY3NTYiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLXByb3ZpZGVyLmRvbWUuZml3YXJlLmRldi9yZWFsbXMvZG9tZSIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJlMmEwNjZmNS00YzAwLTQ5NTYtYjQ0NC03ZWE1ZTE1NmUwNWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50LWNvbnNvbGUiLCJzZXNzaW9uX3N0YXRlIjoiYzFhMTUyYjYtNWJhNy00Y2M4LWFjOTktN2Q2ZTllODIyMjk2IiwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJjMWExNTJiNi01YmE3LTRjYzgtYWM5OS03ZDZlOWU4MjIyOTYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJQcm92aWRlciBMZWFyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicHJvdmlkZXItbGVhciIsImdpdmVuX25hbWUiOiJQcm92aWRlciIsImZhbWlseV9uYW1lIjoiTGVhciJ9.F8vTSNAMc5Fmi-KO0POuaMIxcjdpWxNqfXH3NVdQP18RPKGI5eJr5AGN-yKYncEEzkM5_H28abJc1k_lx7RjnERemqesY5RwoBpTl9_CzdSFnIFbroNOAY4BGgiU-9Md9JsLrENk5Na_uNV_Q85_72tmRpfESqy5dMVoFzWZHj2LwV5dji2n17yf0BjtaWailHdwbnDoSqQab4IgYsExhUkCLCtZ3O418BG9nrSvP-BLQh_EvU3ry4NtnnWxwi5rNk4wzT4j8rxLEAJpMMv-5Ew0z7rbFX3X3UW9WV9YN9eV79-YrmxOksPYahFQwNUXPckCXnM48ZHZ42B0H4iOiA";

        when(appConfig.getIdentityProviderClientSecret()).thenReturn("1234");
        when(appConfig.getIdentityProviderUsername()).thenReturn("user");
        when(appConfig.getIdentityProviderPassword()).thenReturn("4321");
        when(appConfig.getIdentityProviderClientId()).thenReturn("wallet");

        // Mock successful token retrieval
        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, "application/json")
                .body("token")
                .build();
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        Map<String, Object> mapWithToken = Map.of("access_token", token);
        when(objectMapper.readValue(eq("token"), any(TypeReference.class)))
                .thenReturn(mapWithToken);

        // This scenario: No credential => we must generate one
        // We mock 'getCredentialsByUserIdAndType' to throw a NoSuchVerifiableCredentialException
        // or return an empty list. Let's do empty list for simplicity:
        when(credentialService.getCredentialsByUserIdAndType(anyString(), eq(userId), eq("ExampleCredential")))
                .thenReturn(Mono.just(List.of()));

        // Then we generate a new DID
        when(didKeyGeneratorService.generateDidKeyJwkJcsPub())
                .thenReturn(Mono.just(expectedDid));

        // We store the user, returning some user UUID
        UUID storedUserUuid = UUID.randomUUID();
        when(userService.storeUser(anyString(), eq(userId)))
                .thenReturn(Mono.just(storedUserUuid));

        // We save the new credential
        String newCredentialId = UUID.randomUUID().toString();
        when(credentialService.saveCredential(anyString(), eq(storedUserUuid), any(), anyString()))
                .thenReturn(Mono.just(newCredentialId));

        // WHEN / THEN
        StepVerifier.create(ebsiConfig.init())
                .expectNext(expectedDid)
                .verifyComplete();

    }
}


