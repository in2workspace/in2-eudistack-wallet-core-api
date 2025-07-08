package es.in2.wallet.api.facade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.impl.Oid4vciWorkflowImpl;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.domain.utils.ApplicationUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationConstants.JWT_VC;
import static es.in2.wallet.domain.utils.ApplicationUtils.extractResponseType;
import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;
import static org.mockito.Mockito.when;

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
    private ProofJWTService proofJWTService;
    @Mock
    private SignerService signerService;
    @Mock
    private CredentialService credentialService;
    @Mock
    private UserService userService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

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
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().accessToken("ey1234").build();
            List<CredentialResponse.Credentials> credentialList = List.of(
                    new CredentialResponse.Credentials("unsigned_credential")
            );
            CredentialResponse credentialResponse = CredentialResponse.builder().credentials(credentialList).transactionId("123").build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.ACCEPTED).credentialResponse(credentialResponse).build();
            String did = "did:ebsi:123";
            String json = "{\"credential_request\":\"example\"}";
            ObjectMapper objectMapper2 = new ObjectMapper();
            JsonNode jsonNode = objectMapper2.readTree(json);
            String jwtProof = "jwt";

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            UUID credentialId = UUID.randomUUID();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof,tokenResponse,credentialIssuerMetadata,JWT_VC,List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, JWT_VC)).thenReturn(Mono.just(credentialId));
            when(deferredCredentialMetadataService.saveDeferredCredentialMetadata(processId, credentialId, credentialResponse.transactionId(), tokenResponse.accessToken(), credentialIssuerMetadata.deferredCredentialEndpoint())).thenReturn(Mono.empty());

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
            List<CredentialResponse.Credentials> credentialList = List.of(
                    new CredentialResponse.Credentials("ey1234")
            );
            CredentialResponse credentialResponse = CredentialResponse.builder().credentials(credentialList).build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();

            String did = "did:ebsi:123";
            JsonNode jsonNode = new ObjectMapper().readTree("{\"credential_request\":\"example\"}");
            String jwtProof = "jwt";

            Map<String, String> mockedMap = new HashMap<>();
            mockedMap.put("code", "123");
            mockedMap.put("state", "12345");

            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            UUID credentialId = UUID.randomUUID();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, "issuer", did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof, tokenResponse, credentialIssuerMetadata, "jwt_vc_json", List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, "jwt_vc_json")).thenReturn(Mono.just(credentialId));

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
            CredentialResponse credentialResponse = CredentialResponse.builder().build();
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
            UUID credentialId = UUID.randomUUID();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(didKeyGeneratorService.generateDidKey()).thenReturn(Mono.just(did));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, "issuer", did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwt));
            when(oid4vciCredentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, "jwt_vc_json", List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, "jwt_vc_json")).thenReturn(Mono.just(credentialId));

            StepVerifier.create(credentialIssuanceServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }


}

