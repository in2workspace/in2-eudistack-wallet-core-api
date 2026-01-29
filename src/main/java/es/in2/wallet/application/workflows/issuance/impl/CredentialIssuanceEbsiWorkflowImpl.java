package es.in2.wallet.application.workflows.issuance.impl;

import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.CredentialIssuanceEbsiWorkflow;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.infrastructure.ebsi.config.EbsiConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

import static es.in2.wallet.domain.utils.ApplicationUtils.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuanceEbsiWorkflowImpl implements CredentialIssuanceEbsiWorkflow {

    private final CredentialOfferService credentialOfferService;
    private final EbsiConfig ebsiConfig;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final AuthorisationServerMetadataService authorisationServerMetadataService;
    private final OID4VCICredentialService oid4vciCredentialService;
    private final PreAuthorizedService preAuthorizedService;
    private final EbsiIdTokenService ebsiIdTokenService;
    private final EbsiVpTokenService ebsiVpTokenService;
    private final ProofJWTService proofJWTService;
    private final EbsiAuthorisationService ebsiAuthorisationService;
    private final SignerService signerService;
    private final UserService userService;
    private final CredentialService credentialService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;


    /**
     * Identifies the authorization method based on the QR content and proceeds with the credential exchange flow.
     * This method orchestrates the flow to obtain credentials by first retrieving the credential offer,
     * then fetching the issuer and authorisation server metadata, and finally obtaining the credential
     * either through a pre-authorized code grant or an authorization code flow.
     */
    @Override
    public Mono<Void> execute(String processId, String authorizationToken, String qrContent) {
        // get Credential Offer
        return credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)
                //get Issuer Server Metadata
                .flatMap(credentialOffer -> credentialIssuerMetadataService.getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)
                        //get Authorisation Server Metadata
                        .flatMap(credentialIssuerMetadata -> authorisationServerMetadataService.getAuthorizationServerMetadataFromCredentialIssuerMetadata(processId,credentialIssuerMetadata)
                                .flatMap(authorisationServerMetadata -> {
                                    if (credentialOffer.grant().preAuthorizedCodeGrant() != null){
                                        return getCredentialWithPreAuthorizedCodeEbsi(processId,authorizationToken,credentialOffer,authorisationServerMetadata,credentialIssuerMetadata);
                                    }
                                    else {
                                        return getCredentialWithAuthorizedCodeEbsi(processId,authorizationToken,credentialOffer,authorisationServerMetadata,credentialIssuerMetadata);
                                    }
                                })
                        )
                );

    }

    /**
     * Handles the credential acquisition flow using a pre-authorized code grant.
     * This method is chosen when the credential offer includes a pre-authorized code grant.
     */
    private Mono<Void> getCredentialWithPreAuthorizedCodeEbsi(String processId, String authorizationToken, CredentialOffer credentialOffer, AuthorisationServerMetadata authorisationServerMetadata, CredentialIssuerMetadata credentialIssuerMetadata) {
        return ebsiConfig.getDid()
                .flatMap(did -> preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)
                        .flatMap(tokenResponse -> getCredential(
                                processId,authorizationToken,tokenResponse,credentialOffer,credentialIssuerMetadata,did,oid4vciCredentialService.getNonceValue())));
    }


    /**
     * Handles the credential acquisition flow using an authorization code grant.
     * This method is selected when the credential offer does not include a pre-authorized code grant,
     * requiring the user to go through an authorization code flow to obtain the credential.
     */
    private Mono<Void> getCredentialWithAuthorizedCodeEbsi(String processId, String authorizationToken, CredentialOffer credentialOffer, AuthorisationServerMetadata authorisationServerMetadata, CredentialIssuerMetadata credentialIssuerMetadata) {
        // get Credential Offer
        return  ebsiConfig.getDid()
                .flatMap(did -> ebsiAuthorisationService.getRequestWithOurGeneratedCodeVerifier(processId,credentialOffer,authorisationServerMetadata,credentialIssuerMetadata,did)
                        .flatMap(tuple -> extractResponseType(tuple.getT1())
                                .flatMap(responseType -> {
                                    if (responseType.equals("id_token")){
                                        return ebsiIdTokenService.getIdTokenResponse(processId,did,authorisationServerMetadata,tuple.getT1());
                                    }
                                    else if (responseType.equals("vp_token")){
                                       return ebsiVpTokenService.getVpRequest(processId,authorizationToken,authorisationServerMetadata,tuple.getT1());
                                    }
                                    else {
                                        return Mono.error(new RuntimeException("Not known response_type."));
                                    }
                                })
                                .flatMap(params -> ebsiAuthorisationService.sendTokenRequest(tuple.getT2(), did, authorisationServerMetadata,params))
                        )
                        // get Credentials
                        .flatMap(tokenResponse -> getCredential(
                                 processId,authorizationToken,tokenResponse, credentialOffer, credentialIssuerMetadata, did, oid4vciCredentialService.getNonceValue()
                        ))
                );
    }

    /**
     * Constructs a credential request using the nonce from the token response and the issuer's information.
     * The request is then signed using the generated DID and private key to ensure its authenticity.
     */
    private Mono<String> buildAndSignCredentialRequest(String nonce, String did, String issuer) {
        return proofJWTService.buildCredentialRequest(nonce, issuer,did)
                .flatMap(json -> signerService.buildJWTSFromJsonNode(json, did, "proof"));
    }

    private Mono<Void> getCredential(String processId, String authorizationToken, TokenResponse tokenResponse, CredentialOffer credentialOffer, CredentialIssuerMetadata credentialIssuerMetadata, String did, String nonce) {
        Long tokenObtainedAt = Instant.now().getEpochSecond();
        String credentialConfigurationId = List.copyOf(credentialOffer.credentialConfigurationsIds()).get(0);
        CredentialIssuerMetadata.CredentialsConfigurationsSupported config =
                credentialIssuerMetadata.credentialsConfigurationsSupported().get(credentialConfigurationId);

        Mono<String> jwtMono;
        if (config != null && config.cryptographicBindingMethodsSupported() != null
                && !config.cryptographicBindingMethodsSupported().isEmpty()) {
            jwtMono = buildAndSignCredentialRequest(nonce, did, credentialIssuerMetadata.credentialIssuer());
        } else {
            jwtMono = Mono.justOrEmpty((String) null);
        }
        String format = credentialOffer.credentials().get(0).format();
        return jwtMono
                .flatMap(jwt -> oid4vciCredentialService.getCredential(jwt,tokenResponse,tokenObtainedAt,"", credentialIssuerMetadata,format,credentialConfigurationId))
                .flatMap(credentialResponse -> handleCredentialResponse(processId, credentialResponse, authorizationToken, tokenResponse, credentialIssuerMetadata, credentialOffer.credentials().get(0).format()));
    }


    private Mono<Void> handleCredentialResponse(
            String processId,
            CredentialResponseWithStatus credentialResponseWithStatus,
            String authorizationToken,
            TokenResponse tokenResponse,
            CredentialIssuerMetadata credentialIssuerMetadata,
            String format
    ) {
        return getUserIdFromToken(authorizationToken)
                // Store the user
                .flatMap(userId -> userService.storeUser(processId, userId))
                .doOnNext(userUuid ->
                        log.info("ProcessID: {} - Stored userUuid: {}", processId, userUuid.toString())
                )
                // Save the credential
                .flatMap(userUuid -> credentialService.saveCredential(
                        processId,
                        userUuid,
                        credentialResponseWithStatus.credentialResponse(),
                        format
                ))
                .doOnNext(credentialUuid ->
                        log.info("ProcessID: {} - Saved credentialUuid: {}", processId, credentialUuid)
                )
                // If status is ACCEPTED, save deferred metadata; otherwise, skip
                .flatMap(credentialUuid -> {
                    if (credentialResponseWithStatus.statusCode().equals(HttpStatus.ACCEPTED)) {
                        log.info("ProcessID: {} - Status ACCEPTED, saving deferred credential metadata", processId);

                        return deferredCredentialMetadataService.saveDeferredCredentialMetadata(
                                        processId,
                                        credentialUuid,
                                        credentialResponseWithStatus.credentialResponse().transactionId(),
                                        credentialResponseWithStatus.credentialResponse().notificationId(),
                                        tokenResponse.accessToken(),
                                        credentialIssuerMetadata.deferredCredentialEndpoint(),
                                        credentialIssuerMetadata.notificationEndpoint()
                                )
                                .doOnNext(deferredUuid ->
                                        log.info("ProcessID: {} - Deferred credential metadata saved with UUID: {}", processId, deferredUuid)
                                )
                                .then();
                    } else {
                        log.info("ProcessID: {} - Status is {}, skipping deferred metadata",
                                processId, credentialResponseWithStatus.statusCode());
                        return Mono.empty();
                    }
                })
                .doOnError(error ->
                        log.error("ProcessID: {} - handleCredentialResponse error: {}",
                                processId, error.getMessage(), error)
                )
                .then();
    }

}
