package es.in2.wallet.api.ebsi.comformance.facade;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.impl.CredentialIssuanceEbsiWorkflowImpl;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.domain.utils.ApplicationUtils;
import es.in2.wallet.infrastructure.ebsi.config.EbsiConfig;
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
import reactor.util.function.Tuples;

import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationUtils.extractResponseType;
import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceEbsiWorkflowImplTest {

    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private EbsiConfig ebsiConfig;
    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    @Mock
    private AuthorisationServerMetadataService authorisationServerMetadataService;
    @Mock
    private PreAuthorizedService preAuthorizedService;
    @Mock
    private OID4VCICredentialService oid4vciCredentialService;
    @Mock
    private ProofJWTService proofJWTService;
    @Mock
    private SignerService signerService;
    @Mock
    private EbsiAuthorisationService ebsiAuthorisationService;
    @Mock
    private EbsiIdTokenService ebsiIdTokenService;
    @Mock
    private EbsiVpTokenService ebsiVpTokenService;
    @Mock
    private CredentialService credentialService;
    @Mock
    private UserService userService;

    @InjectMocks
    private CredentialIssuanceEbsiWorkflowImpl ebsiCredentialServiceFacade;

    @Test
    void getCredentialWithPreAuthorizedCodeEbsi_UserEntityExists_PersistCredential() throws JsonProcessingException {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";
            CredentialOffer.Credential credential = CredentialOffer.Credential.builder().format("jwt_vc").types(List.of("LEARCredential")).build();
            CredentialOffer.Grant grant = CredentialOffer.Grant.builder().preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build()).build();
            CredentialOffer credentialOffer = CredentialOffer.builder().grant(grant).credentials(List.of(credential)).credentialConfigurationsIds(Set.of("LEARCredential")).build();
            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();
            CredentialIssuerMetadata.CredentialsConfigurationsSupported configurationsSupported = CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                    .format("jwt_vc_json")
                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                    .build();
            Map<String, CredentialIssuerMetadata.CredentialsConfigurationsSupported> credentialConfigurationsSupported = new HashMap<>();
            credentialConfigurationsSupported.put("LEARCredential", configurationsSupported);
            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("https://issuer.dome-marketplace.eu")
                    .credentialsConfigurationsSupported(credentialConfigurationsSupported)
                    .build();
            TokenResponse tokenResponse = TokenResponse.builder().build();
            CredentialResponse credentialResponse = CredentialResponse.builder().build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();
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
            when(ebsiConfig.getDid()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format(), List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse,credentialOffer.credentials().get(0).format())).thenReturn(Mono.just(credentialId));

            StepVerifier.create(ebsiCredentialServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }

    @Test
    void getCredentialWithPreAuthorizedCodeEbsi_UserEntityNoExists_UpdatesEntityWithCredential() throws JsonProcessingException {
        try (MockedStatic<ApplicationUtils> ignored = Mockito.mockStatic(ApplicationUtils.class)) {
            String processId = "processId";
            String authorizationToken = "authToken";
            String qrContent = "qrContent";
            CredentialOffer.Credential credential = CredentialOffer.Credential.builder().format("jwt_vc").types(List.of("LEARCredential")).build();
            CredentialOffer.Grant grant = CredentialOffer.Grant.builder().preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder().build()).build();
            CredentialOffer credentialOffer = CredentialOffer.builder().grant(grant).credentials(List.of(credential)).credentialConfigurationsIds(Set.of("LEARCredential")).build();
            AuthorisationServerMetadata authorisationServerMetadata = AuthorisationServerMetadata.builder().build();
            CredentialIssuerMetadata.CredentialsConfigurationsSupported configurationsSupported = CredentialIssuerMetadata.CredentialsConfigurationsSupported.builder()
                    .format("jwt_vc_json")
                    .cryptographicBindingMethodsSupported(List.of("did:key"))
                    .build();
            Map<String, CredentialIssuerMetadata.CredentialsConfigurationsSupported> credentialConfigurationsSupported = new HashMap<>();
            credentialConfigurationsSupported.put("LEARCredential", configurationsSupported);
            CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                    .credentialIssuer("https://issuer.dome-marketplace.eu")
                    .credentialsConfigurationsSupported(credentialConfigurationsSupported)
                    .build();
            TokenResponse tokenResponse = TokenResponse.builder().build();
            CredentialResponse credentialResponse = CredentialResponse.builder().build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();
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
            when(ebsiConfig.getDid()).thenReturn(Mono.just(did));
            when(preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format(), List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, credentialOffer.credentials().get(0).format())).thenReturn(Mono.just(credentialId));

            StepVerifier.create(ebsiCredentialServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }

    @Test
    void getCredentialWithAuthorizedCodeEbsiIdToken_UserEntityExists_UpdatesEntityWithCredential() throws JsonProcessingException {
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
                    .credentialIssuer("https://issuer.dome-marketplace.eu")
                    .credentialsConfigurationsSupported(credentialConfigurationsSupported)
                    .build();

            TokenResponse tokenResponse = TokenResponse.builder().build();
            CredentialResponse credentialResponse = CredentialResponse.builder().build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();
            String did = "did:ebsi:123";
            String json = "{\"credential_request\":\"example\"}";
            ObjectMapper objectMapper2 = new ObjectMapper();
            JsonNode jsonNode = objectMapper2.readTree(json);
            String jwtProof = "jwt";
            Map<String, String> mockedMap = new HashMap<>();
            mockedMap.put("code", "123");
            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            UUID credentialId = UUID.randomUUID();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(ebsiConfig.getDid()).thenReturn(Mono.just(did));
            when(ebsiAuthorisationService.getRequestWithOurGeneratedCodeVerifier(processId, credentialOffer, authorisationServerMetadata, credentialIssuerMetadata, did)).thenReturn(Mono.just(Tuples.of("jwt", "codeVerifier")));
            when(extractResponseType("jwt")).thenReturn(Mono.just("id_token"));
            when(ebsiIdTokenService.getIdTokenResponse(processId, did, authorisationServerMetadata, "jwt")).thenReturn(Mono.just(mockedMap));
            when(ebsiAuthorisationService.sendTokenRequest("codeVerifier", did, authorisationServerMetadata, mockedMap)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format(), List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, credentialOffer.credentials().get(0).format())).thenReturn(Mono.just(credentialId));

            StepVerifier.create(ebsiCredentialServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
        }
    }

    @Test
    void getCredentialWithAuthorizedCodeEbsiVpToken_UserEntityExists_UpdatesEntityWithCredential() throws JsonProcessingException {
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
                    .credentialIssuer("https://issuer.dome-marketplace.eu")
                    .credentialsConfigurationsSupported(credentialConfigurationsSupported)
                    .build();
            TokenResponse tokenResponse = TokenResponse.builder().build();
            CredentialResponse credentialResponse = CredentialResponse.builder().build();
            CredentialResponseWithStatus credentialResponseWithStatus = CredentialResponseWithStatus.builder().statusCode(HttpStatus.OK).credentialResponse(credentialResponse).build();
            String did = "did:ebsi:123";
            String json = "{\"credential_request\":\"example\"}";
            ObjectMapper objectMapper2 = new ObjectMapper();
            JsonNode jsonNode = objectMapper2.readTree(json);
            String jwtProof = "jwt";
            Map<String, String> mockedMap = new HashMap<>();
            mockedMap.put("code", "123");
            String userIdStr = UUID.randomUUID().toString();
            UUID userUuid = UUID.fromString(userIdStr);
            UUID credentialId = UUID.randomUUID();

            when(getUserIdFromToken(authorizationToken)).thenReturn(Mono.just(userIdStr));
            when(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)).thenReturn(Mono.just(credentialOffer));
            when(credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)).thenReturn(Mono.just(credentialIssuerMetadata));
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata)).thenReturn(Mono.just(authorisationServerMetadata));
            when(ebsiConfig.getDid()).thenReturn(Mono.just(did));
            when(ebsiAuthorisationService.getRequestWithOurGeneratedCodeVerifier(processId, credentialOffer, authorisationServerMetadata, credentialIssuerMetadata, did)).thenReturn(Mono.just(Tuples.of("jwt", "codeVerifier")));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(ebsiVpTokenService.getVpRequest(processId, authorizationToken, authorisationServerMetadata, "jwt")).thenReturn(Mono.just(mockedMap));
            when(ebsiAuthorisationService.sendTokenRequest("codeVerifier", did, authorisationServerMetadata, mockedMap)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwtProof));
            when(oid4vciCredentialService.getCredential(jwtProof, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format(), List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));
            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, credentialOffer.credentials().get(0).format())).thenReturn(Mono.just(credentialId));

            StepVerifier.create(ebsiCredentialServiceFacade.execute(processId, authorizationToken, qrContent)).verifyComplete();
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
                    .credentialIssuer("https://issuer.dome-marketplace.eu")
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
            when(authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId, credentialIssuerMetadata))
                    .thenReturn(Mono.just(authorisationServerMetadata));
            when(ebsiConfig.getDid()).thenReturn(Mono.just(did));
            when(ebsiAuthorisationService.getRequestWithOurGeneratedCodeVerifier(processId, credentialOffer, authorisationServerMetadata, credentialIssuerMetadata, did))
                    .thenReturn(Mono.just(Tuples.of("jwt", "codeVerifier")));
            when(extractResponseType("jwt")).thenReturn(Mono.just("vp_token"));
            when(ebsiVpTokenService.getVpRequest(processId, authorizationToken, authorisationServerMetadata, "jwt")).thenReturn(Mono.just(mockedMap));
            when(ebsiAuthorisationService.sendTokenRequest("codeVerifier", did, authorisationServerMetadata, mockedMap)).thenReturn(Mono.just(tokenResponse));
            when(proofJWTService.buildCredentialRequest(null, credentialIssuerMetadata.credentialIssuer(), did)).thenReturn(Mono.just(jsonNode));
            when(signerService.buildJWTSFromJsonNode(jsonNode, did, "proof")).thenReturn(Mono.just(jwt));

            when(oid4vciCredentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format(),
                    List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0))).thenReturn(Mono.just(credentialResponseWithStatus));

            when(userService.storeUser(processId, userIdStr)).thenReturn(Mono.just(userUuid));
            when(credentialService.saveCredential(processId, userUuid, credentialResponse, credentialOffer.credentials().get(0).format())).thenReturn(Mono.just(credentialId));

            StepVerifier.create(ebsiCredentialServiceFacade.execute(processId, authorizationToken, qrContent)).
                    verifyComplete();
        }
    }




}

