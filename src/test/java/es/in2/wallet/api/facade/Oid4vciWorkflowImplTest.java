package es.in2.wallet.api.facade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.impl.Oid4vciWorkflowImpl;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.domain.utils.ApplicationUtils;
import es.in2.wallet.infrastructure.core.config.NotificationRequestWebSocketHandler;
import es.in2.wallet.infrastructure.core.config.WebSocketSessionManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationConstants.JWT_VC;
import static es.in2.wallet.domain.utils.ApplicationUtils.extractResponseType;
import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class Oid4vciWorkflowImplTest {

    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    @Mock
    private AuthorisationServerMetadataService authorisationServerMetadataService;
    @Mock
    private PreAuthorizedService preAuthorizedService;
    @Mock
    private DidKeyGeneratorService didKeyGeneratorService;
    @Mock
    private OID4VCICredentialService oid4vciCredentialService;
    @Mock
    private OID4VCIDeferredCredentialService oid4vciDeferredCredentialService;
    @Mock
    private ProofJWTService proofJWTService;
    @Mock
    private SignerService signerService;
    @Mock
    private CredentialService credentialService;
    @Mock
    private UserService userService;
    @Mock private WebSocketSessionManager sessionManager;
    @Mock private NotificationRequestWebSocketHandler notificationRequestWebSocketHandler;
    @Mock private NotificationClientService notificationClientService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();
    @InjectMocks
    private Oid4vciWorkflowImpl credentialIssuanceServiceFacade;

    @Test
    void getCredentialWithPreAuthorizedCodeDOMEProfile() throws JsonProcessingException {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";
            CredentialOffer.Grant grant = CredentialOffer.Grant.builder().preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build()).build();
            CredentialOffer credentialOffer = CredentialOffer.builder().grant(grant).credentialConfigurationsIds(Set.of("LEARCredential")).build();
            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialsConfigurationsSupported(Map.of("LEARCredential",
                            CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                                    .format(JWT_VC)
                                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                                    .build()))
                    .credentialIssuer("issuer")
                    .deferredCredentialEndpoint("https://example.com/deferred")
                    .notificationEndpoint("https://example.com/notify")
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken("ey1234")
                    .refreshToken("1234")
                    .expiresIn(50000).build();
            List<CredentialResponse.Credential> credentialList = List.of(
                    new CredentialResponse.Credential("unsigned_credential")
            );
            CredentialResponse credentialResponse = CredentialResponse.builder().credentials(credentialList).transactionId("123").notificationId(null).build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.ACCEPTED).credentialResponse(credentialResponse).build();
            String did = "did:ebsi:123";
            String json = "{\"credential_request\":\"example\"}";
            ObjectMapper objectMapper2 = new ObjectMapper();
            JsonNode jsonNode = objectMapper2.readTree(json);
            String jwtProof = "jwt";

            String userIdStr = UUID.randomUUID().toString();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            String credentialConfigurationId = List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0);
            when(oid4vciCredentialService.getCredential(eq(jwtProof),eq(tokenResponse),anyLong(), isNull(), eq(credentialIssuerMetadata),eq(JWT_VC),eq(credentialConfigurationId))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(oid4vciDeferredCredentialService.handleDeferredCredential(any(), isNull(), anyString(), isNull(), eq(credentialIssuerMetadata)))
                    .thenReturn(Mono.empty());

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }

    @Test
    void getCredentialWithAuthorizedCodeEbsiVpToken_UserEntityExists_UpdatesEntityWithCredential() throws JsonProcessingException {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {

            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";

            CredentialOffer.Credential credential = CredentialOffer.Credential.builder()
                    .format("jwt_vc")
                    .types(List.of("LEARCredential"))
                    .build();

            CredentialOffer.Grant grant = CredentialOffer.Grant.builder()
                    .authorizationCodeGrant(CredentialOffer.Grant.AuthorizationCodeGrant.builder().issuerState("mock-issuer-state").build())
                    .build();

            CredentialOffer credentialOffer = CredentialOffer.builder()
                    .grant(grant)
                    .credentials(List.of(credential))
                    .credentialConfigurationsIds(Set.of("lear-configuration-id"))
                    .build();

            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder()
                    .authorizationEndpoint("https://example.com/authorize")
                    .tokenEndpoint("https://example.com/token")
                    .build();

            Map<String, CredentialIssuerMetadata.CredentialsConfigurationsSupported> supportedMap = Map.of(
                    "lear-configuration-id", CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                            .format("jwt_vc_json")
                            .cryptographicBindingMethodsSupported(List.of("did:key"))
                            .build());

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("issuer")
                    .credentialsConfigurationsSupported(supportedMap)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().build();
            List<CredentialResponse.Credential> credentialList = List.of(
                    new CredentialResponse.Credential("ey1234")
            );
            CredentialResponse credentialResponse = CredentialResponse.builder().credentials(credentialList).notificationId("").build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();

            String did = "did:ebsi:123";
            JsonNode jsonNode = new ObjectMapper().readTree("{\"credential_request\":\"example\"}");
            String jwtProof = "jwt";

            Map<String, String> mockedMap = new HashMap<>();
            mockedMap.put("code", "123");
            mockedMap.put("state", "12345");

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            String credentialId = UUID.randomUUID().toString();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, "issuer", did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            String credentialConfigurationId = List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0);
            when(oid4vciCredentialService.getCredential(eq(jwtProof), eq(tokenResponse), anyLong(),  eq(authorisationServerMetadata.tokenEndpoint()), eq(credentialIssuerMetadata), eq("jwt_vc_json"), eq(credentialConfigurationId))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, "jwt_vc_json")).thenReturn(Mono.just(credentialId));
            WebSocketSession mockSession = mock(WebSocketSession.class);
            when(sessionManager.getSession(userIdStr)).thenReturn(Mono.just(mockSession));

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }
    @Test
    void testGetCredentialWithCryptographicBinding() throws JsonProcessingException {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";

            CredentialOffer.Credential credential = CredentialOffer.Credential.builder().format("jwt_vc").types(List.of("LEARCredential")).build();
            CredentialOffer.Grant grant = CredentialOffer.Grant.builder().authorizationCodeGrant(CredentialOffer.Grant.AuthorizationCodeGrant.builder().build()).build();
            CredentialOffer credentialOffer = CredentialOffer.builder().grant(grant).credentials(List.of(credential)).credentialConfigurationsIds(Set.of("LEARCredential")).build();

            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();

            CredentialIssuerMetadata.CredentialsConfigurationsSupported configurationsSupported = CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                    .format("jwt_vc_json")
                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                    .build();

            Map<String, CredentialIssuerMetadata.CredentialsConfigurationsSupported> credentialConfigurationsSupported = new HashMap<>();
            credentialConfigurationsSupported.put("LEARCredential", configurationsSupported);

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("issuer")
                    .credentialsConfigurationsSupported(credentialConfigurationsSupported)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().build();
            CredentialResponse credentialResponse = CredentialResponse.builder()
                    .notificationId("notif-1")
                    .credentials(List.of(new CredentialResponse.Credential("unsigned_credential")))
                    .build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();
            String did = "did:ebsi:123";
            String json = "{\"credential_request\":\"example\"}";
            ObjectMapper objectMapper2 = new ObjectMapper();
            JsonNode jsonNode = objectMapper2.readTree(json);
            String jwt = "jwt";
            Map<String, String> mockedMap = new HashMap<>();
            mockedMap.put("code", "123");

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            String credentialId = UUID.randomUUID().toString();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, "issuer", did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwt));
            when(oid4vciCredentialService.getCredential(eq(jwt), eq(tokenResponse), anyLong(),  isNull(), eq(credentialIssuerMetadata), eq("jwt_vc_json"), eq(List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0)))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, "jwt_vc_json")).thenReturn(Mono.just(credentialId));

            WebSocketSession mockSession = mock(WebSocketSession.class);
            when(sessionManager.getSession(userIdStr)).thenReturn(Mono.just(mockSession));
            doNothing().when(notificationRequestWebSocketHandler)
                    .sendNotificationDecisionRequest(eq(mockSession), any(WebSocketServerNotificationMessage.class));
            when(notificationRequestWebSocketHandler.getDecisionResponses(userIdStr))
                    .thenReturn(Flux.just("ACCEPTED"));
            when(notificationClientService.notifyIssuer(
                    anyString(), anyString(), anyString(),
                    any(), anyString(), any(CredentialIssuerMetadata.class)
            )).thenReturn(Mono.empty());

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }

    @Test
    void execute_shouldGetSession_sendDecisionRequest_andDetachedAccepted_shouldNotifyIssuer() throws Exception {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {

            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            String credentialId = "cred-1";

            CredentialOffer.Grant grant = CredentialOffer.Grant.builder()
                    .preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build())
                    .build();

            CredentialOffer credentialOffer = CredentialOffer.builder()
                    .grant(grant)
                    .credentialConfigurationsIds(Set.of("LEARCredential"))
                    .build();

            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("issuer")
                    .deferredCredentialEndpoint("https://issuer.example/deferred")
                    .notificationEndpoint("https://issuer.example/notify")
                    .credentialsConfigurationsSupported(Map.of(
                            "LEARCredential",
                            CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                                    .format(JWT_VC)
                                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                                    .build()
                    ))
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().accessToken("issuer-access-token").build();
            String vcJson = """
        {
          "issuer": "did:issuer:123",
          "validUntil": "2030-12-31",
          "credentialSubject": {
            "mandate": {
              "mandatee": { "firstName": "John", "lastName": "Doe" },
              "mandator": { "organization": "ACME" }
            }
          }
        }
        """;

            CredentialResponse credentialResponse = CredentialResponse.builder()
                    .notificationId("notif-1")
                    .transactionId("tx-1")
                    .credentials(List.of(new CredentialResponse.Credential(vcJson)))
                    .build();

            CredentialResponseWithStatus crws = CredentialResponseWithStatus.builder()
                    .statusCode(HttpStatus.OK)
                    .credentialResponse(credentialResponse)
                    .build();

            String did = "did:key:123";
            JsonNode jsonNode = new ObjectMapper().readTree("{\"credential_request\":\"example\"}");
            String jwtProof = "jwt-proof";

            WebSocketSession mockSession = mock(WebSocketSession.class);

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent))
                    .thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer))
                    .thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata))
                    .thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken))
                    .thenReturn(Mono.just(tokenResponse));

            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did))
                    .thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof"))
                    .thenReturn(Mono.just(jwtProof));

            when(oid4vciCredentialService.getCredential(
                    eq(jwtProof),
                    eq(tokenResponse),
                    anyLong(),
                    isNull(),
                    eq(credentialIssuerMetadata),
                    eq(JWT_VC),
                    eq("LEARCredential")
            )).thenReturn(Mono.just(crws));

            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, JWT_VC))
                    .thenReturn(Mono.just(credentialId));

            String userUuidStr = userUuid.toString();

            when(sessionManager.getSession(userUuidStr)).thenReturn(Mono.just(mockSession));

            when(notificationRequestWebSocketHandler.getDecisionResponses(userUuidStr))
                    .thenReturn(Flux.just("ACCEPTED"));

            doNothing().when(notificationRequestWebSocketHandler)
                    .sendNotificationDecisionRequest(eq(mockSession), any(WebSocketServerNotificationMessage.class));

            when(notificationClientService.notifyIssuer(
                    anyString(), anyString(), anyString(),
                    any(), anyString(), any(CredentialIssuerMetadata.class)
            )).thenReturn(Mono.empty());


            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent))
                    .verifyComplete();

            verify(sessionManager).getSession(userUuidStr);
            verify(notificationRequestWebSocketHandler)
                    .sendNotificationDecisionRequest(eq(mockSession), any(WebSocketServerNotificationMessage.class));

            verify(notificationClientService).notifyIssuer(
                    eq(processId),
                    eq(tokenResponse.accessToken()),
                    eq("notif-1"),
                    eq(NotificationEvent.CREDENTIAL_ACCEPTED),
                    anyString(),
                    eq(credentialIssuerMetadata)
            );
        }
    }
    @Test
    void execute_whenDecisionRejected_shouldDeleteCredential_andNotifyDeleted() throws Exception {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            String credentialId = "cred-1";

            CredentialOffer.Grant grant = CredentialOffer.Grant.builder()
                    .preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build())
                    .build();

            CredentialOffer credentialOffer = CredentialOffer.builder()
                    .grant(grant)
                    .credentialConfigurationsIds(Set.of("LEARCredential"))
                    .build();

            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("issuer")
                    .deferredCredentialEndpoint("https://issuer.example/deferred")
                    .notificationEndpoint("https://issuer.example/notify")
                    .credentialsConfigurationsSupported(Map.of(
                            "LEARCredential",
                            CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                                    .format(JWT_VC)
                                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                                    .build()
                    ))
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().accessToken("issuer-access-token").build();

            String vcJson = """
        { "issuer":"did:issuer:123", "credentialSubject": { "mandate": { "mandatee": { "firstName":"A" } } } }
        """;

            CredentialResponse credentialResponse = CredentialResponse.builder()
                    .notificationId("notif-1")
                    .transactionId("tx-1")
                    .credentials(List.of(new CredentialResponse.Credential(vcJson)))
                    .build();

            CredentialResponseWithStatus crws = CredentialResponseWithStatus.builder()
                    .statusCode(HttpStatus.OK)
                    .credentialResponse(credentialResponse)
                    .build();

            String did = "did:key:123";
            JsonNode jsonNode = new ObjectMapper().readTree("{\"credential_request\":\"example\"}");
            String jwtProof = "jwt-proof";

            WebSocketSession mockSession = mock(WebSocketSession.class);

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));

            when(oid4vciCredentialService.getCredential(
                    eq(jwtProof),
                    eq(tokenResponse),
                    anyLong(),
                    isNull(),
                    eq(credentialIssuerMetadata),
                    eq(JWT_VC),
                    eq("LEARCredential")
            )).thenReturn(Mono.just(crws));

            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, JWT_VC)).thenReturn(Mono.just(credentialId));

            when(sessionManager.getSession(userIdStr)).thenReturn(Mono.just(mockSession));

            doNothing().when(notificationRequestWebSocketHandler)
                    .sendNotificationDecisionRequest(eq(mockSession), any(WebSocketServerNotificationMessage.class));

            when(notificationRequestWebSocketHandler.getDecisionResponses(userIdStr))
                    .thenReturn(Flux.just("REJECTED"));

            when(credentialService.deleteCredential(processId, credentialId, userIdStr))
                    .thenReturn(Mono.empty());

            when(notificationClientService.notifyIssuer(anyString(), anyString(), anyString(), any(), anyString(), any()))
                    .thenReturn(Mono.empty());

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent))
                    .verifyComplete();

            verify(credentialService).deleteCredential(processId, credentialId, userIdStr);

            verify(notificationClientService).notifyIssuer(
                    eq(processId),
                    eq(tokenResponse.accessToken()),
                    eq("notif-1"),
                    eq(NotificationEvent.CREDENTIAL_DELETED),
                    anyString(),
                    eq(credentialIssuerMetadata)
            );
        }
    }

    @Test
    void execute_whenDecisionFailure_shouldDeleteCredential_andNotifyFailure() throws Exception {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {

            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            String credentialId = "cred-1";

            CredentialOffer.Grant grant = CredentialOffer.Grant.builder()
                    .preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build())
                    .build();

            CredentialOffer credentialOffer = CredentialOffer.builder()
                    .grant(grant)
                    .credentialConfigurationsIds(Set.of("LEARCredential"))
                    .build();

            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();

            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("issuer")
                    .notificationEndpoint("https://issuer.example/notify")
                    .credentialsConfigurationsSupported(Map.of(
                            "LEARCredential",
                            CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                                    .format(JWT_VC)
                                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                                    .build()
                    ))
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().accessToken("issuer-access-token").build();

            String vcJson = "{ \"issuer\":\"did:issuer:123\", \"credentialSubject\": {\"mandate\":{}} }";

            CredentialResponse credentialResponse = CredentialResponse.builder()
                    .notificationId("notif-1")
                    .transactionId("tx-1")
                    .credentials(List.of(new CredentialResponse.Credential(vcJson)))
                    .build();

            CredentialResponseWithStatus crws = CredentialResponseWithStatus.builder()
                    .statusCode(HttpStatus.OK)
                    .credentialResponse(credentialResponse)
                    .build();

            String did = "did:key:123";
            JsonNode jsonNode = new ObjectMapper().readTree("{\"credential_request\":\"example\"}");
            String jwtProof = "jwt-proof";

            WebSocketSession mockSession = mock(WebSocketSession.class);

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));

            when(oid4vciCredentialService.getCredential(
                    eq(jwtProof),
                    eq(tokenResponse),
                    anyLong(),
                    isNull(),
                    eq(credentialIssuerMetadata),
                    eq(JWT_VC),
                    eq("LEARCredential")
            )).thenReturn(Mono.just(crws));


            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, JWT_VC)).thenReturn(Mono.just(credentialId));

            when(sessionManager.getSession(userIdStr)).thenReturn(Mono.just(mockSession));
            doNothing().when(notificationRequestWebSocketHandler)
                    .sendNotificationDecisionRequest(eq(mockSession), any(WebSocketServerNotificationMessage.class));

            when(notificationRequestWebSocketHandler.getDecisionResponses(userIdStr))
                    .thenReturn(Flux.just("FAILURE"));

            when(credentialService.deleteCredential(processId, credentialId, userIdStr))
                    .thenReturn(Mono.empty());

            when(notificationClientService.notifyIssuer(anyString(), anyString(), anyString(), any(), anyString(), any()))
                    .thenReturn(Mono.empty());

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent))
                    .verifyComplete();

            verify(credentialService).deleteCredential(processId, credentialId, userIdStr);

            verify(notificationClientService).notifyIssuer(
                    eq(processId),
                    eq(tokenResponse.accessToken()),
                    eq("notif-1"),
                    eq(NotificationEvent.CREDENTIAL_FAILURE),
                    anyString(),
                    eq(credentialIssuerMetadata)
            );
        }
    }

}

