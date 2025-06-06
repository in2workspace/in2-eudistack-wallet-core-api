package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.domain.exceptions.FailedDeserializingException;
import es.in2.wallet.domain.exceptions.FailedSerializingException;
import es.in2.wallet.domain.services.OID4VCICredentialService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class OID4VCICredentialServiceImpl implements OID4VCICredentialService {

    private final ObjectMapper objectMapper;
    private final WebClientConfig webClient;

    @Override
    public Mono<CredentialResponseWithStatus> getCredential(
            String jwt,
            TokenResponse tokenResponse,
            CredentialIssuerMetadata credentialIssuerMetadata,
            String format,
            String credentialConfigurationId,
            String cryptographicBinding
    ) {
        String processId = MDC.get(PROCESS_ID);

        return buildCredentialRequest(jwt, format, credentialConfigurationId, cryptographicBinding)
                .doOnSuccess(request ->
                        log.info("ProcessID: {} - CredentialRequest: {}", processId, request)
                )
                // Perform the POST request using postCredentialRequest
                .flatMap(request ->
                        postCredentialRequest(
                                tokenResponse.accessToken(),
                                credentialIssuerMetadata.credentialEndpoint(),
                                request
                        )
                )
                .doOnSuccess(responseWithStatus ->
                        log.info(
                                "ProcessID: {} - Credential POST Response: {}",
                                processId,
                                responseWithStatus.credentialResponse()
                        )
                )
                // Handle deferred or immediate credential response
                .flatMap(this::handleCredentialResponse)
                .doOnSuccess(finalResponse ->
                        log.info(
                                "ProcessID: {} - Final CredentialResponseWithStatus: {}",
                                processId,
                                finalResponse
                        )
                );
    }

    /**
     * Retrieves a deferred credential for DOME if needed.
     * Returns a Mono<CredentialResponseWithStatus> for consistency.
     */
    @Override
    public Mono<CredentialResponseWithStatus> getCredentialDomeDeferredCase(
            String transactionId,
            String accessToken,
            String deferredEndpoint
    ) {
        String processId = MDC.get(PROCESS_ID);

        DeferredCredentialRequest deferredCredentialRequest = DeferredCredentialRequest
                .builder()
                .transactionId(transactionId)
                .build();

        return postCredentialRequest(accessToken, deferredEndpoint, deferredCredentialRequest)
                .doOnSuccess(responseWithStatus ->
                        log.info(
                                "ProcessID: {} - Deferred Credential ResponseWithStatus: {}",
                                processId,
                                responseWithStatus
                        )
                );
    }

    /**
     * Handles immediate or deferred credential responses:
     *  - If acceptanceToken is present, waits 10 seconds then calls handleDeferredCredential.
     *  - Otherwise, returns the existing response.
     * Returns a Mono<CredentialResponseWithStatus>.
     */
    private Mono<CredentialResponseWithStatus> handleCredentialResponse(
            CredentialResponseWithStatus responseWithStatus
    ) {
        return Mono.just(responseWithStatus);
    }

    /**
     * Makes a POST request and returns a Mono<CredentialResponseWithStatus> containing
     * the parsed CredentialResponse and the HTTP status code.
     */
    private Mono<CredentialResponseWithStatus> postCredentialRequest(
            String accessToken,
            String credentialEndpoint,
            Object credentialRequest
    ) {
        try {
            // Convert the request to JSON
            String requestJson = objectMapper.writeValueAsString(credentialRequest);
            log.info("Request JSON: {}", requestJson);

            return webClient.centralizedWebClient()
                    .post()
                    .uri(credentialEndpoint)
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.AUTHORIZATION, BEARER + accessToken)
                    .bodyValue(requestJson)
                    .exchangeToMono(response -> {
                        if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                            return Mono.error(
                                    new RuntimeException("There was an error during the credential request, error: " + response)
                            );
                        } else {
                            log.info("Credential response retrieved: {}", response);
                            // Parse the body to a CredentialResponse, then wrap it in CredentialResponseWithStatus
                            return response.bodyToMono(String.class)
                                    .handle((responseBody, sink) -> {
                                        try {
                                            System.out.println("XIVATO 100: "+responseBody);
                                            CredentialResponse credentialResponse =
                                                    objectMapper.readValue(responseBody, CredentialResponse.class);
                                            System.out.println("XIVATO 1: "+credentialResponse);
                                            sink.next(CredentialResponseWithStatus.builder()
                                                    .credentialResponse(credentialResponse)
                                                    .statusCode(response.statusCode())
                                                    .build());
                                            System.out.println("XIVATO 2: "+credentialResponse);
                                        } catch (Exception e) {
                                            log.error("Error parsing credential response: {}", e.getMessage());
                                            sink.error(new FailedDeserializingException(
                                                    "Error parsing credential response: " + responseBody
                                            ));
                                        }
                                    });
                        }
                    });
        } catch (Exception e) {
            log.error("Error while serializing CredentialRequest: {}", e.getMessage());
            return Mono.error(new FailedSerializingException("Error while serializing Credential Request"));
        }
    }

    /**
     * Builds the request object CredentialRequest depending on the format and types.
     */
    private Mono<?> buildCredentialRequest(String jwt, String format, String credentialConfigurationId, String cryptographicBinding) {
        try{
            if(credentialConfigurationId != null) {
                if (format.equals(JWT_VC_JSON)) {
                    if (cryptographicBinding != null) {
                        return Mono.just(
                                CredentialRequest.builder()
                                        .format(format)
                                        .credentialConfigurationId(credentialConfigurationId)
                                        .proof(CredentialRequest.Proofs.builder().proofType("jwt").jwt(List.of(jwt)).build())
                                        .build()
                        ).doOnNext(req ->
                                log.debug("Credential Request Body for DOME Profile with proof: {}", req)
                        );
                    } else {
                        return Mono.just(
                                CredentialRequest.builder()
                                        .format(format)
                                        .credentialConfigurationId(credentialConfigurationId)
                                        .build()
                        ).doOnNext(req ->
                                log.debug("Credential Request Body for DOME Profile: {}", req)
                        );
                    }

                }
                return Mono.error(new IllegalArgumentException(
                        "Format not supported: " + format
                ));
            }
            return Mono.error(new IllegalArgumentException(
                    "Credentials configurations ids not provided"
            ));

        }catch (Exception error){
            return Mono.error(new RuntimeException(
                    "Error while building credential request, error: " + error));
        }
    }
}