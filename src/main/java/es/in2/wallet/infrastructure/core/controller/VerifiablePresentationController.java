package es.in2.wallet.infrastructure.core.controller;

import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.workflows.presentation.Oid4vpWorkflow;
import es.in2.wallet.application.workflows.presentation.AttestationExchangeTurnstileWorkflow;
import es.in2.wallet.application.dto.CredentialsBasicInfo;
import es.in2.wallet.application.dto.VcSelectorResponse;
import es.in2.wallet.infrastructure.core.config.SwaggerConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.wallet.domain.utils.ApplicationUtils.getCleanBearerToken;

@RestController
@RequestMapping("/api/v1/vp")
@Slf4j
@RequiredArgsConstructor
public class VerifiablePresentationController {

    private final AttestationExchangeTurnstileWorkflow attestationExchangeTurnstileWorkflow;
    private final Oid4vpWorkflow oid4vpWorkflow;
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Save DID",
            description = "Save a Decentralized Identifier (DID)",
            tags = (SwaggerConfig.TAG_PUBLIC)
    )
    public Mono<Void> createVerifiablePresentation(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
                                                   @RequestBody VcSelectorResponse vcSelectorResponse) {
        String processId = UUID.randomUUID().toString();
        MDC.put("processId", processId);
        return getCleanBearerToken(authorizationHeader)
                .flatMap(authorizationToken -> oid4vpWorkflow.buildVerifiablePresentationWithSelectedVCs(processId, authorizationToken, vcSelectorResponse)).doOnSuccess(aVoid -> log.info("Attestation exchange successful"));
    }
    @PostMapping("/cbor")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
            summary = "Verifiable Presentation in CBOR format",
            description = "Create a Verifiable Presentation in CBOR format",
            tags = (SwaggerConfig.TAG_PUBLIC)
    )
    @ApiResponse(responseCode = "200", description = "Verifiable presentation retrieved successfully.")
    @ApiResponse(responseCode = "400", description = "Invalid request.")
    @ApiResponse(responseCode = "500", description = "Internal server error.")
    public Mono<String> createVerifiablePresentationInCborFormat(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader, @RequestBody VerifiableCredential credential) {
        log.debug("VerifiablePresentationController.createVerifiablePresentationInCborFormat()");

        String processId = UUID.randomUUID().toString();

        MDC.put("processId", processId);
        return getCleanBearerToken(authorizationHeader)
                .flatMap(authorizationToken -> attestationExchangeTurnstileWorkflow.createVerifiablePresentationForTurnstile(processId, authorizationToken, credential));
    }
}
