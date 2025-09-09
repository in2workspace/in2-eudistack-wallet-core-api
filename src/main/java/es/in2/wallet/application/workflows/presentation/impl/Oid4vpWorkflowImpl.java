package es.in2.wallet.application.workflows.presentation.impl;

import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.presentation.Oid4vpWorkflow;
import es.in2.wallet.domain.services.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static es.in2.wallet.domain.utils.ApplicationConstants.LEAR_CREDENTIAL_EMPLOYEE_SCOPE;
import static es.in2.wallet.domain.utils.ApplicationUtils.getUserIdFromToken;

@Slf4j
@Service
@RequiredArgsConstructor
public class Oid4vpWorkflowImpl implements Oid4vpWorkflow {

    private final AuthorizationRequestService authorizationRequestService;
    private final AuthorizationResponseService authorizationResponseService;
    private final VerifierValidationService verifierValidationService;
    private final PresentationService presentationService;
    private final CredentialService credentialService;

    @Override
    public Mono<VcSelectorRequest> processAuthorizationRequest(String processId, String authorizationToken, String qrContent) {
        log.info("ProcessID: {} - Processing a Verifiable Credential Login Request", processId);
        return authorizationRequestService.getJwtRequestObjectFromUri(processId, qrContent)
                .flatMap(jwtAuthorizationRequest -> verifierValidationService.verifyIssuerOfTheAuthorizationRequest(processId, jwtAuthorizationRequest))
                .flatMap(jwtAuthorizationRequest -> authorizationRequestService.getAuthorizationRequestFromJwtAuthorizationRequestJWT(processId, jwtAuthorizationRequest))
                .flatMap(authorizationRequest -> getSelectableCredentialsRequiredToBuildThePresentation(processId, authorizationToken, authorizationRequest.scope())
                        .flatMap(credentials -> buildSelectableVCsRequest(authorizationRequest,credentials)));
    }

    @Override
    // TODO: Refactor this method to return Flux<VerifiableCredential> instead of Mono<List<VerifiableCredential>>
    public Mono<List<VerifiableCredential>> getSelectableCredentialsRequiredToBuildThePresentation(String processId, String authorizationToken, List<String> scope) {
        return getUserIdFromToken(authorizationToken)
                .flatMap(userId -> Flux.fromIterable(scope)
                        .flatMap(element -> {
                            // Verificar si el elemento es igual a LEAR_CREDENTIAL_EMPLOYEE_SCOPE
                            String credentialType = element.equals(LEAR_CREDENTIAL_EMPLOYEE_SCOPE)
                                    ? "LEARCredentialEmployee"
                                    : element;


                            return  credentialService.getCredentialsByUserIdAndType(processId, userId, credentialType);
                        })
                        .collectList()  // This will collect all lists into a single list
                        .flatMap(lists -> {
                            List<VerifiableCredential> allCredentials = new ArrayList<>();
                            lists.forEach(allCredentials::addAll); // Combine all lists into one
                            return Mono.just(allCredentials);
                        })
                );
    }

    private Mono<VcSelectorRequest> buildSelectableVCsRequest(AuthorizationRequestOIDC4VP authorizationRequestOIDC4VP, List<VerifiableCredential> selectableVCs) {
        return Mono.fromCallable(() -> VcSelectorRequest.builder()
                .redirectUri(authorizationRequestOIDC4VP.responseUri())
                .state(authorizationRequestOIDC4VP.state())
                .nonce(authorizationRequestOIDC4VP.nonce())
                .selectableVcList(selectableVCs)
                .build());
    }

    @Override
    public Mono<Void> buildVerifiablePresentationWithSelectedVCs(String processId, String authorizationToken, VcSelectorResponse vcSelectorResponse) {
        log.info("Starting to build Verifiable Presentation for processId: {}", processId);
        // Get the Verifiable Credentials which will be used for the Presentation from the Wallet Data Service
        return
                // Create the Verifiable Presentation
               generateAudience()
                       .doOnSubscribe(subscription -> log.debug("Fetching audience for processId: {}", processId))
                       .flatMap(audience -> {
                           log.info("Audience generated for processId: {}", processId);
                           return presentationService.createSignedVerifiablePresentation(processId, authorizationToken, vcSelectorResponse, vcSelectorResponse.nonce(), audience);
                       })
                       .doOnSuccess(verifiablePresentation -> log.debug("Successfully created Verifiable Presentation for processId: {}", processId))
                       .doOnError(error -> log.warn("Error occurred while creating Verifiable Presentation for processId: {}: {}", processId, error.getMessage()))
                       // Build the Authentication Response
                       // Send the Authentication Response to the Verifier
                       .flatMap(verifiablePresentation -> {
                           log.info("Sending Authentication Response with Verifiable Presentation for processId: {}", processId);
                           return authorizationResponseService.buildAndPostAuthorizationResponseWithVerifiablePresentation(processId, vcSelectorResponse, verifiablePresentation, authorizationToken);
                       })
                       .doOnSuccess(aVoid -> log.debug("Successfully sent Authorization Response for processId: {}", processId))
                       .doOnError(error -> log.warn("Error occurred while sending Authorization Response for processId: {}: {}", processId, error.getMessage()))
                       .then()
                       .doOnTerminate(() -> log.info("Completed processing Verifiable Presentation for processId: {}", processId));

    }


    private static Mono<String> generateAudience() {
        return Mono.just("https://self-issued.me/v2");
    }

}
