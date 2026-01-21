package es.in2.wallet.application.workflows.issuance.impl;

import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.Oid4vciWorkflow;
import es.in2.wallet.domain.services.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;

@Slf4j
@Service
@RequiredArgsConstructor
public class Oid4vciWorkflowImpl implements Oid4vciWorkflow {

    private final CredentialOfferService credentialOfferService;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final AuthorisationServerMetadataService authorisationServerMetadataService;
    private final PreAuthorizedService preAuthorizedService;
    private final OID4VCICredentialService oid4vciCredentialService;
    private final DidKeyGeneratorService didKeyGeneratorService;
    private final ProofJWTService proofJWTService;
    private final SignerService signerService;
    private final UserService userService;
    private final CredentialService credentialService;
    private final DeferredCredentialMetadataService deferredCredentialMetadataService;


    @Override
    public Mono<Void> execute(String processId, String authorizationToken, String qrContent) {
        // get Credential Offer
        return credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, qrContent)
                //get Issuer Server Metadata
                .flatMap(credentialOffer -> credentialIssuerMetadataService
                        .getCredentialIssuerMetadataFromCredentialOffer(processId, credentialOffer)
                        //get Authorisation Server Metadata
                        .flatMap(credentialIssuerMetadata -> authorisationServerMetadataService
                                .getAuthorizationServerMetadataFromCredentialIssuerMetadata(
                                        processId,
                                        credentialIssuerMetadata
                                )
                                .flatMap(authorisationServerMetadata ->
                                        getCredentialWithPreAuthorizedCodeFlow(
                                            processId,
                                            authorizationToken,
                                            credentialOffer,
                                            authorisationServerMetadata,
                                            credentialIssuerMetadata
                                        )
                                )));
    }

    /**
     * Orchestrates the flow to get a credential using the Pre-Authorized Code Flow
     * as defined in the OpenID4VCI specification.
     */
    private Mono<Void> getCredentialWithPreAuthorizedCodeFlow(String processId, String authorizationToken, CredentialOffer credentialOffer, AuthorisationServerMetadata authorisationServerMetadata, CredentialIssuerMetadata credentialIssuerMetadata) {
        log.info("ProcessId: {} - Getting Dome Profile Credential with Pre-Authorized Code", processId);

        return generateDid()
                .flatMap(did -> getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata, authorizationToken)
                        .flatMap(tokenResponse -> {
                            Long tokenObtainedAt = Instant.now().getEpochSecond();
                            List<String> credentialConfigurationsIds = List.copyOf(credentialOffer.credentialConfigurationsIds());
                            if (credentialConfigurationsIds.isEmpty()) {
                                return Mono.error(new RuntimeException("No credential configurations IDs found"));
                            }
                            log.info("TokenResponse: {}", tokenResponse);
                            log.info("Configuration IDs: {}", credentialConfigurationsIds);
                            String credentialConfigurationId = credentialConfigurationsIds.get(0);
                            CredentialIssuerMetadata.CredentialsConfigurationsSupported config =
                                    credentialIssuerMetadata.credentialsConfigurationsSupported().get(credentialConfigurationId);
                            log.info("Configuration: {}", config);
                            Mono<String> jwtMono;
                            if (config != null && config.cryptographicBindingMethodsSupported() != null
                                    && !config.cryptographicBindingMethodsSupported().isEmpty()) {
                                jwtMono = buildAndSignCredentialRequest(oid4vciCredentialService.getNonceValue(), did, credentialIssuerMetadata.credentialIssuer());
                            } else {
                                jwtMono = Mono.just("");
                            }
                            log.debug("JWT: {}", jwtMono);
                            return jwtMono.flatMap(jwt ->
                                    retrieveCredentialFormatFromCredentialIssuerMetadataByCredentialConfigurationId(credentialConfigurationId, credentialIssuerMetadata)
                                            .flatMap(format ->
                                                    oid4vciCredentialService.getCredential(jwt, tokenResponse, tokenObtainedAt, authorisationServerMetadata.tokenEndpoint(), credentialIssuerMetadata, format, credentialConfigurationId)
                                                            .flatMap(credentialResponseWithStatus ->
                                                                    handleCredentialResponse(processId, credentialResponseWithStatus, authorizationToken, tokenResponse, credentialIssuerMetadata, format)
                                                            )
                                            )
                            );

                        })
                );
    }


    /**
     * Retrieves a pre-authorized token from the authorization server.
     * This token is used in later requests to authenticate and authorize operations.
     */
    private Mono<TokenResponse> getPreAuthorizedToken(String processId, CredentialOffer credentialOffer,
                                                      AuthorisationServerMetadata authorisationServerMetadata,
                                                      String authorizationToken) {
        return preAuthorizedService.getPreAuthorizedToken(processId, credentialOffer, authorisationServerMetadata,
                authorizationToken);
    }

    /**
     * Generates a new ES256r1 EC key pair for signing requests.
     * The generated key pair is then saved in a vault for secure storage and later retrieval.
     * The method returns a map containing key pair details, including the DID.
     */
    private Mono<String> generateDid() {
        return didKeyGeneratorService.generateDidKey();
    }

    /**
     * Constructs a credential request using the nonce from the token response and the issuer's information.
     * The request is then signed using the generated DID and private key to ensure its authenticity.
     */
    private Mono<String> buildAndSignCredentialRequest(String nonce, String did, String issuer) {
        return proofJWTService.buildCredentialRequest(nonce, issuer, did)
                .flatMap(json -> signerService.buildJWTSFromJsonNode(json, did, "proof"));
    }

    private Mono<String> retrieveCredentialFormatFromCredentialIssuerMetadataByCredentialConfigurationId(
            String credentialConfigurationId, CredentialIssuerMetadata credentialIssuerMetadata) {
        return Mono.justOrEmpty(credentialIssuerMetadata.credentialsConfigurationsSupported())
                .map(configurationsSupported -> configurationsSupported.get(credentialConfigurationId))
                .map(CredentialIssuerMetadata.CredentialsConfigurationsSupported::format)
                .switchIfEmpty(Mono.error(new NoSuchElementException("No configuration found for ID: " + credentialConfigurationId)));
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
                .doOnNext(credentialId ->
                        log.info("ProcessID: {} - Saved credentialId: {}", processId, credentialId)
                )
                // If status is ACCEPTED, save deferred metadata; otherwise, skip
                .flatMap(credentialId -> {
                    if (credentialResponseWithStatus.statusCode().equals(HttpStatus.ACCEPTED)) {
                        log.info("ProcessID: {} - Status ACCEPTED, saving deferred credential metadata", processId);

                        return deferredCredentialMetadataService.saveDeferredCredentialMetadata(
                                        processId,
                                        credentialId,
                                        credentialResponseWithStatus.credentialResponse().transactionId(),
                                        tokenResponse.accessToken(),
                                        credentialIssuerMetadata.deferredCredentialEndpoint()
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
