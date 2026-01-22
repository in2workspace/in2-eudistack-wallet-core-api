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
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

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
            Long tokenObtainedAt,
            String tokenEndpoint,
            CredentialIssuerMetadata credentialIssuerMetadata,
            String format,
            String credentialConfigurationId
    ) {
        String processId = MDC.get(PROCESS_ID);

        return buildCredentialRequest(jwt, format, credentialConfigurationId)
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
                .flatMap(responseWithStatus1 -> {
                    HttpStatusCode httpStatusCode = responseWithStatus1.statusCode();
                    if (httpStatusCode.equals(HttpStatusCode.valueOf(200))) {
                        return handleCredentialResponse(responseWithStatus1);
                    } else if (httpStatusCode.equals(HttpStatusCode.valueOf(202))) {
                        return Mono.fromRunnable(() ->
                                        handleDeferredCredential(
                                                TokenInfo.builder()
                                                        .accessToken(tokenResponse.accessToken())
                                                        .refreshToken(tokenResponse.refreshToken())
                                                        .tokenObtainedAt(tokenObtainedAt)
                                                        .expiresIn(tokenResponse.expiresIn())
                                                        .build(),
                                                tokenEndpoint,
                                                responseWithStatus1.credentialResponse().transactionId(),
                                                responseWithStatus1.credentialResponse().interval(),
                                                credentialIssuerMetadata)
                                                .subscribeOn(Schedulers.boundedElastic())
                                                .subscribe(
                                                        r -> log.info("ProcessID: {} - Background deferred credential completed", processId),
                                                        e -> log.error("ProcessID: {} - Background deferred credential failed", processId, e)
                                                ))
                                .then(Mono.empty());
                    } else {
                        return Mono.error(new IllegalArgumentException("Unexpected HTTP status: " + httpStatusCode));
                    }
                })
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

    @Override
    public String getNonceValue() {
        //TO DO: Call nonce_endpoint
        return null;
    }

    /**
     * Handles immediate or deferred credential responses:
     * - If acceptanceToken is present, waits 10 seconds then calls handleDeferredCredential.
     * - Otherwise, returns the existing response.
     * Returns a Mono<CredentialResponseWithStatus>.
     */
    //TODO: Handle deferred or immediate credential response
    private Mono<CredentialResponseWithStatus> handleCredentialResponse(
            CredentialResponseWithStatus responseWithStatus
    ) {
        return Mono.just(responseWithStatus);

    }

    /**
     * Handles the recursive deferred flow. Returns a Mono<CredentialResponse>:
     * - Parses the server response (JSON) into a CredentialResponse.
     * - Checks if a new acceptanceToken is present; if so, recurses.
     * - If the credential is available, returns it.
     */
    public Mono<Void> handleDeferredCredential(
            TokenInfo tokenInfo,
            String tokenEndpoint,
            String transactionId,
            Long interval,
            CredentialIssuerMetadata credentialIssuerMetadata
    ) {
        System.out.println("Deferred Metadata: " + credentialIssuerMetadata.deferredCredentialEndpoint());
        return Mono.delay(Duration.ofSeconds(interval))
                .then(ensureValidToken(tokenInfo, tokenEndpoint))
                .flatMap(validTokenInfo ->
                        webClient.centralizedWebClient()
                                .post()
                                .uri(credentialIssuerMetadata.deferredCredentialEndpoint())
                                .contentType(MediaType.APPLICATION_JSON)
                                .header(HEADER_AUTHORIZATION, BEARER + validTokenInfo.accessToken())
                                .bodyValue(Map.of("transaction_id", transactionId))
                                .exchangeToMono(response -> {
                                    if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                                        return Mono.error(new RuntimeException(
                                                "Error during the deferred credential request, error: " + response
                                        ));
                                    } else {
                                        log.info("Deferred credential response retrieved");
                                        return response.bodyToMono(String.class);
                                    }
                                })
                                .flatMap(responseBody -> {
                                    try {
                                        log.debug("Deferred flow body: {}", responseBody);
                                        CredentialResponseWithStatus credentialResponseWithStatus = objectMapper.readValue(responseBody, CredentialResponseWithStatus.class);

                                        // Recursive call if a new transactionId is received
                                        if (credentialResponseWithStatus.credentialResponse().transactionId() != null
                                                && !credentialResponseWithStatus.credentialResponse().transactionId().equals(transactionId)) {
                                            return handleDeferredCredential(validTokenInfo, tokenEndpoint, credentialResponseWithStatus.credentialResponse().transactionId(), credentialResponseWithStatus.credentialResponse().interval(), credentialIssuerMetadata);
                                        }
                                        // If the credential is available, return it
                                        if (credentialResponseWithStatus.credentialResponse().credentials().get(0).credential() != null) {
                                            log.debug("Deferred credential signature completed for: {}", transactionId);
                                            return Mono.empty();
                                        }
                                        return Mono.error(new IllegalStateException(
                                                "No credential or new transaction id received in deferred flow"
                                        ));
                                    } catch (Exception e) {
                                        log.error("Error while processing deferred CredentialResponse", e);
                                        return Mono.error(new FailedDeserializingException(
                                                "Error processing deferred CredentialResponse: " + responseBody
                                        ));
                                    }
                                }))
                .doFirst(() -> log.debug("Starting deferred credential signature for: {}", transactionId));
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
                                            CredentialResponse credentialResponse =
                                                    objectMapper.readValue(responseBody, CredentialResponse.class);

                                            sink.next(CredentialResponseWithStatus.builder()
                                                    .credentialResponse(credentialResponse)
                                                    .statusCode(response.statusCode())
                                                    .build());
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
    private Mono<?> buildCredentialRequest(String jwt, String format, String credentialConfigurationId) {
        try {
            if (credentialConfigurationId != null) {
                if (format.equals(JWT_VC_JSON)) {
                    if (jwt != null && !jwt.isBlank()) {
                        return Mono.just(
                                CredentialRequest.builder()
                                        .format(format)
                                        .credentialConfigurationId(credentialConfigurationId)
                                        .proof(
                                                CredentialRequest.Proof.builder()
                                                        .proofType("jwt")
                                                        .jwt(jwt)
                                                        .build())
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

        } catch (Exception error) {
            return Mono.error(new RuntimeException(
                    "Error while building credential request, error: " + error));
        }
    }

    private Mono<TokenInfo> ensureValidToken(TokenInfo tokenInfo, String tokenUrl) {
        System.out.println("HOLAAAAAAAA");
        long currentTime = Instant.now().getEpochSecond();
        long expiry = tokenInfo.tokenObtainedAt() + tokenInfo.expiresIn();
        long safetyWindow = 10;

        if (currentTime < (expiry - safetyWindow)) {
            return Mono.just(tokenInfo);
        }

        log.debug("Access token expired or about to expire. Refreshing token");
        return refreshToken(tokenInfo.refreshToken(), tokenUrl)
                .flatMap(newTokenResponse ->
                        Mono.just(TokenInfo.builder()
                                .accessToken(newTokenResponse.accessToken())
                                .refreshToken(newTokenResponse.refreshToken())
                                .tokenObtainedAt(Instant.now().getEpochSecond())
                                .expiresIn(newTokenResponse.expiresIn())
                                .build()))
                .onErrorResume(e -> {
                    log.error("Refresh token failed or expired. Clearing session.", e);
                    return Mono.error(new IllegalStateException(
                            "Refresh token expired. Please request a new Credential Offer."
                    ));
                })
                .doOnSuccess(t -> log.debug("Access token successfully refreshed"));
    }

    private Mono<TokenResponse> refreshToken(String refreshToken, String tokenUrl) {
        Map<String, String> formDataMap = new HashMap<>();
        formDataMap.put("grant_type", REFRESH_TOKEN_GRANT_TYPE);
        formDataMap.put("refresh_token", refreshToken);

        String xWwwFormUrlencodedBody = formDataMap.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" +
                        URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        return webClient.centralizedWebClient()
                .post()
                .uri(tokenUrl)
                .header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)
                .bodyValue(xWwwFormUrlencodedBody)
                .exchangeToMono(response ->
                        response.bodyToMono(TokenResponse.class));
    }
}