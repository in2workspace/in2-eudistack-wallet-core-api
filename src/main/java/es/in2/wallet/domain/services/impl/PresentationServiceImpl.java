package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.application.dto.CredentialsBasicInfo;
import es.in2.wallet.application.dto.VcSelectorResponse;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.dto.VerifiablePresentation;
import es.in2.wallet.application.ports.AppConfig;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.domain.services.PresentationService;
import es.in2.wallet.domain.services.SignerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;
import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;

@Slf4j
@Service
@RequiredArgsConstructor
public class PresentationServiceImpl implements PresentationService {

    private final ObjectMapper objectMapper;
    private final SignerService signerService;
    private final CredentialService credentialService;

    private final AppConfig appConfig;

    /**
     * Creates and signs a Verifiable Presentation (VP) using the selected Verifiable Credentials (VCs).
     * This method retrieves the subject DID from the first VC, constructs an unsigned VP, and signs it.
     *
     * @param authorizationToken   The authorization token to identify the user.
     * @param vcSelectorResponse   The response containing the selected VCs for the VP.
     * @param nonce                A unique nonce for the VP.
     * @param audience             The intended audience of the VP.
     */
    @Override
    public Mono<String> createSignedVerifiablePresentation(String processId, String authorizationToken, VcSelectorResponse vcSelectorResponse,String nonce, String audience) {
        return createSignedVerifiablePresentation(processId, authorizationToken, nonce, audience, vcSelectorResponse.selectedVcList());
    }

    /**
     * Creates and signs a Verifiable Presentation (VP) using the selected Verifiable Credential (VC).
     * This method retrieves the subject DID from the first VC, constructs an unsigned VP, and signs it.
     *
     * @param authorizationToken   The authorization token to identify the user.
     * @param verifiableCredential The selected VC for the VP.
     * @param nonce                A unique nonce for the VP.
     * @param audience             The intended audience of the VP.
     */
    @Override
    public Mono<String> createSignedTurnstileVerifiablePresentation(String processId, String authorizationToken, VerifiableCredential verifiableCredential, String nonce, String audience) {
        return createSignedVerifiablePresentation(processId, authorizationToken, nonce, audience, List.of(verifiableCredential));
    }

    private Mono<String> createSignedVerifiablePresentation(
            String processId,
            String authorizationToken,
            String nonce,
            String audience,
            List<VerifiableCredential> selectedVcList
    ) {
        log.info("Starting to create Signed Verifiable Presentation for processId: {}", processId);

        // Step 1: Get User ID from the authorization token
        return getUserIdFromToken(authorizationToken)
                .doOnSubscribe(sub -> log.debug("Getting user ID from token, processId: {}", processId))

                // Step 2: Get Verifiable Credentials in the chosen format (only once)
                .flatMap(userId -> {
                    log.debug("User ID obtained: {}, processId: {}", userId, processId);
                    return getVerifiableCredentials(processId, userId, selectedVcList);
                })
                .doOnSubscribe(sub -> log.debug("Fetching Verifiable Credentials, processId: {}", processId))

                // Step 3: Extract DID from the first Verifiable Credential
                .flatMap(verifiableCredentialsList -> getSubjectDidFromTheFirstVcOfTheList(verifiableCredentialsList)
                        .flatMap(did -> {
                            log.debug("DID extracted successfully: {}, processId: {}", did, processId);

                            // Step 4: Create the unsigned presentation
                            return createUnsignedPresentationForSigning(verifiableCredentialsList, did, nonce, audience)
                                    .doOnSubscribe(sub -> log.debug("Creating unsigned Verifiable Presentation, processId: {}", processId))

                                    // Step 5: Build JWT for Verifiable Presentation
                                    .flatMap(document -> signerService.buildJWTSFromJsonNode(document, did, "vp")
                                            .doOnSubscribe(sub -> log.debug("Building JWT for Verifiable Presentation, processId: {}", processId))

                                            // Step 6: Encode the presentation
                                            .flatMap(jwt -> encodePresentation(jwt)
                                                    .doOnSubscribe(sub -> log.debug("Encoding Verifiable Presentation, processId: {}", processId))
                                                    .doOnSuccess(encodedPresentation -> log.info(
                                                            "ProcessID: {} - Verifiable Presentation created successfully: {}",
                                                            processId, encodedPresentation
                                                    ))
                                            )
                                    );
                        })
                )

                // Handle errors
                .onErrorResume(e -> {
                    log.warn("Error in creating Verifiable Presentation, processId: {}: {}", processId, e.getMessage());
                    return Mono.error(e);
                });
    }

    /**
     * Retrieves a list of Verifiable Credential based on the VCs selected in the VcSelectorResponse.
     *
     * @param selectedVcList       The selected VCs.
     */
    private Mono<List<String>> getVerifiableCredentials(String processId, String userId, List<VerifiableCredential> selectedVcList) {
        return Flux.fromIterable(selectedVcList)
                .flatMap(credential -> credentialService.getCredentialDataByIdAndUserId(processId,userId, credential.id()))
                .collectList();
    }

    /**
     * Extracts the subject DID from the first Verifiable Credential in the list.
     *
     * @param verifiableCredentialsList The list of VC JWTs.
     */
    private Mono<String> getSubjectDidFromTheFirstVcOfTheList(List<String> verifiableCredentialsList) {
        return Mono.fromCallable(() -> {
            // Check if the list is not empty
            try {
                if (!verifiableCredentialsList.isEmpty()) {
                    // Get the first verifiable credential's JWT and parse it
                    String verifiableCredential = verifiableCredentialsList.get(0);
                    SignedJWT parsedVerifiableCredential = SignedJWT.parse(verifiableCredential);
                    // Extract the subject DID from the JWT claims
                    return (String) parsedVerifiableCredential.getJWTClaimsSet().getClaim("sub");
                } else {
                    // Throw an exception if the credential list is empty
                    throw new NoSuchElementException("Verifiable credentials list is empty");
                }
            } catch (Exception e) {
                throw new IllegalStateException("Error obtaining the subject DID from the verifiable credential" + e);
            }
        });
    }

    /**
     * Creates an unsigned Verifiable Presentation containing the selected VCs.
     *
     * @param vcs       The list of VC JWTs to include in the VP.
     * @param holderDid The DID of the holder of the VPs.
     * @param nonce     A unique nonce for the VP.
     * @param audience  The intended audience of the VP.
     */
    private Mono<JsonNode> createUnsignedPresentationForSigning(
            List<String> vcs,
            String holderDid,
            String nonce,
            String audience) {
        return Mono.fromCallable(() -> {
            String id = "urn:uuid:" + UUID.randomUUID();

            VerifiablePresentation vpBuilder = VerifiablePresentation
                    .builder()
                    .id(id)
                    .holder(holderDid)
                    .context(List.of(JSONLD_CONTEXT_W3C_2018_CREDENTIALS_V1))
                    .type(List.of(VERIFIABLE_PRESENTATION))
                    .verifiableCredential(vcs)
                    .build();

            Instant issueTime = Instant.now();
            Instant expirationTime = issueTime.plus(VERIFIABLE_PRESENTATION_EXPIRATION_TIME, ChronoUnit.valueOf(VERIFIABLE_PRESENTATION_EXPIRATION_UNIT));
            Map<String, Object> vpParsed = JWTClaimsSet.parse(objectMapper.writeValueAsString(vpBuilder)).getClaims();
            JWTClaimsSet.Builder payloadBuilder = new JWTClaimsSet.Builder()
                    .issuer(holderDid)
                    .subject(holderDid)
                    .notBeforeTime(java.util.Date.from(issueTime))
                    .expirationTime(java.util.Date.from(expirationTime))
                    .issueTime(java.util.Date.from(issueTime))
                    .jwtID(id)
                    .claim("vp", vpParsed)
                    .claim("nonce", nonce);

            if (audience != null) {
                payloadBuilder.audience(audience);
            }

            JWTClaimsSet payload = payloadBuilder.build();
            log.debug(payload.toString());
            return objectMapper.readTree(payload.toString());
        });
    }

    private Mono<String> encodePresentation(String vp) {
        return Mono.fromCallable(() -> Base64.getUrlEncoder().withoutPadding().encodeToString(vp.getBytes()));
    }


}
