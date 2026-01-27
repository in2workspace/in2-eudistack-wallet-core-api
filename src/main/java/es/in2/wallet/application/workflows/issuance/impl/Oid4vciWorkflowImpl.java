package es.in2.wallet.application.workflows.issuance.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.issuance.Oid4vciWorkflow;
import es.in2.wallet.domain.services.*;
import es.in2.wallet.domain.services.impl.NotificationClientServiceImpl;
import es.in2.wallet.infrastructure.core.config.NotificationRequestWebSocketHandler;
import es.in2.wallet.infrastructure.core.config.WebSocketSessionManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
    private final WebSocketSessionManager sessionManager;
    private final NotificationRequestWebSocketHandler notificationRequestWebSocketHandler;
    private final NotificationClientService notificationClientService;
    private final ObjectMapper objectMapper;


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
                                                    oid4vciCredentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, format, credentialConfigurationId)
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
        final long timeoutSeconds = 65;

        return getUserIdFromToken(authorizationToken)
                // Store the user
                .flatMap(userId -> userService.storeUser(processId, userId)
                        .doOnNext(userUuid ->
                                log.info("ProcessID: {} - Stored userUuid: {}", processId, userUuid.toString())
                        )
                        .map(userUuid -> reactor.util.function.Tuples.of(userId, userUuid))
                )
                // Save the credential
                .flatMap(userTuple -> credentialService.saveCredential(
                        processId,
                        userTuple.getT2(), // userUuid
                        credentialResponseWithStatus.credentialResponse(),
                        format
                )
                        .doOnNext(credentialId ->
                                log.info("ProcessID: {} - Saved credentialId: {}", processId, credentialId)
                        )
                        .map(credentialId -> reactor.util.function.Tuples.of(
                                userTuple.getT1(), // userId
                                userTuple.getT2(), // userUuid
                                credentialId
                        ))
                )
                // If status is ACCEPTED, save deferred metadata; otherwise, skip
                .flatMap(tuple -> {
                    String credentialId = tuple.getT3();
                    if (credentialResponseWithStatus.statusCode().equals(HttpStatus.ACCEPTED)) {
                        log.info("ProcessID: {} - Status ACCEPTED, saving deferred credential metadata", processId);

                        return deferredCredentialMetadataService.saveDeferredCredentialMetadata(
                                        processId,
                                        credentialId,
                                        credentialResponseWithStatus.credentialResponse().transactionId(),
                                        credentialResponseWithStatus.credentialResponse().notificationId(),
                                        tokenResponse.accessToken(),
                                        credentialIssuerMetadata.deferredCredentialEndpoint(),
                                        credentialIssuerMetadata.notificationEndpoint()
                                )
                                .doOnNext(deferredUuid ->
                                        log.info("ProcessID: {} - Deferred credential metadata saved with UUID: {}", processId, deferredUuid)
                                )
                                .thenReturn(tuple);
                    } else {
                        log.info("ProcessID: {} - Status is {}, skipping deferred metadata",
                                processId, credentialResponseWithStatus.statusCode());
                        return Mono.just(tuple);
                    }
                })
                .flatMap(tuple -> {
                    String userId = tuple.getT1();
                    String credentialId = tuple.getT3();
                    String notificationId = credentialResponseWithStatus.credentialResponse().notificationId();
                    if (notificationId == null || notificationId.isBlank()) {
                        log.warn("ProcessID: {} - No notificationId in credentialResponse. Skipping issuer notification. credentialId={}",
                                processId, credentialId);
                        return Mono.empty();
                    }

                    return sessionManager.getSession(userId)
                            .switchIfEmpty(Mono.error(new RuntimeException("WebSocket session not found for userId=" + userId)))
                            .flatMap(session ->
                                    buildCredentialPreview(credentialResponseWithStatus.credentialResponse(), credentialIssuerMetadata)
                                            .doOnNext(preview -> notificationRequestWebSocketHandler.sendNotificationDecisionRequest(
                                                    session,
                                                    WebSocketServerNotificationMessage.builder()
                                                            .decision(true)
                                                            .credentialPreview(preview)
                                                            .timeout(timeoutSeconds)
                                                            .build()
                                            ))
                                            .then(notificationRequestWebSocketHandler.getDecisionResponses(userId)
                                                    .next()
                                                    .timeout(java.time.Duration.ofSeconds(timeoutSeconds))
                                            )
                            )
                            .flatMap(decision -> {
                                boolean accepted = "ACCEPTED".equalsIgnoreCase(decision);

                                if (accepted) {
                                    log.info("ProcessID: {} - User ACCEPTED credentialId={}", processId, credentialId);
                                    return notificationClientService.notifyIssuer(
                                            processId,
                                            tokenResponse.accessToken(),
                                            notificationId,
                                            NotificationEvent.CREDENTIAL_ACCEPTED,
                                            "Credential accepted by user and successfully stored in wallet",
                                            credentialIssuerMetadata
                                    );
                                }

                                log.info("ProcessID: {} - User REJECTED credentialId={}", processId, credentialId);

                                return credentialService.deleteCredential(processId, credentialId, userId)
                                        .onErrorResume(e -> {
                                            log.warn("ProcessID: {} - Failed to delete credentialId={} on reject: {}",
                                                    processId, credentialId, e.getMessage(), e);
                                            return Mono.empty();
                                        })
                                        .then(notificationClientService.notifyIssuer(
                                                processId,
                                                tokenResponse.accessToken(),
                                                notificationId,
                                                NotificationEvent.CREDENTIAL_DELETED,
                                                "User rejected credential",
                                                credentialIssuerMetadata
                                        ));
                            })
                            .onErrorResume(Throwable.class, e -> {
                                log.warn("ProcessID: {} - Timeout waiting user decision. credentialId={}", processId, credentialId);
                                return notificationClientService.notifyIssuer(
                                        processId,
                                        tokenResponse.accessToken(),
                                        notificationId,
                                        NotificationEvent.CREDENTIAL_FAILURE,
                                        "Timeout waiting for user decision",
                                        credentialIssuerMetadata
                                );
                            });
                })
                .doOnError(error ->
                        log.error("ProcessID: {} - handleCredentialResponse error: {}",
                                processId, error.getMessage(), error)
                )
                .then();
    }

    private Mono<CredentialPreview> buildCredentialPreview(CredentialResponse credentialResponse,CredentialIssuerMetadata issuerMetadata) {
        System.out.println("XIVATO1");
        System.out.println(credentialResponse.credentials());
        System.out.println(issuerMetadata);
        return Mono.justOrEmpty(credentialResponse)
                .flatMap(cr -> Mono.justOrEmpty(cr.credentials()))
                .filter(list -> !list.isEmpty())
                .map(list -> list.get(0))
                .map(CredentialResponse.Credentials::credential)
                .filter(cred -> cred != null && !cred.isBlank())
                .flatMap(this::decodeVc)
                .map(vcJson -> mapVcToPreview(vcJson, issuerMetadata))
                .onErrorResume(e -> {
                    log.warn("Credential preview generation failed: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<JsonNode> decodeVc(String credential) {
        return Mono.defer(() -> {
            System.out.println("XIVATO2");
            try {
                // JWT VC
                if (credential.chars().filter(c -> c == '.').count() == 2) {
                    String payloadB64 = credential.split("\\.")[1];
                    byte[] decoded = Base64.getUrlDecoder().decode(payloadB64);
                    JsonNode payload = objectMapper.readTree(decoded);
                    System.out.println("XIVATO3");

                    return Mono.just(payload.has("vc") ? payload.get("vc") : payload);
                }

                // JSON VC
                return Mono.just(objectMapper.readTree(credential));

            } catch (Exception e) {
                return Mono.error(e);
            }
        });
    }

    private CredentialPreview mapVcToPreview(JsonNode vcJson, CredentialIssuerMetadata md) {
        System.out.println("XIVATO5");
        System.out.println(vcJson.toPrettyString());

        JsonNode cs = vcJson.path("credentialSubject");
        System.out.println(cs.toPrettyString());
        String issuer = cs.path("issuer").path("commonName").asText(null);

        if (issuer == null || issuer.isBlank()) {
            JsonNode issuerNode = vcJson.path("issuer");
            issuer = issuerNode.isTextual()
                    ? issuerNode.asText()
                    : issuerNode.path("id").asText(null);
        }

        String subjectName = null;
        JsonNode mandatee = cs.path("mandate").path("mandatee");
        String firstName = mandatee.path("firstName").asText(null);
        String lastName  = mandatee.path("lastName").asText(null);

        if (firstName != null || lastName != null) {
            subjectName = ((firstName != null) ? firstName : "") + " " + ((lastName != null) ? lastName : "");
            subjectName = subjectName.trim();
            if (subjectName.isBlank()) subjectName = null;
        }
        String organization = cs.path("mandate").path("mandator").path("organization").asText(null);
        String expirationDate = vcJson.path("validUntil").asText(null);

        return new CredentialPreview(
                issuer,
                subjectName,
                organization,
                expirationDate
        );
    }



}
