package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.domain.exceptions.FailedDeserializingException;
import es.in2.wallet.domain.services.OID4VCIDeferredCredentialService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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
public class OID4VCIDeferredCredentialServiceImpl implements OID4VCIDeferredCredentialService {

    private final ObjectMapper objectMapper;
    private final WebClientConfig webClient;

    @Override
    public Mono<CredentialResponseWithStatus> handleDeferredCredential(
            TokenInfo tokenInfo,
            String tokenEndpoint,
            String transactionId,
            Long interval,
            CredentialIssuerMetadata credentialIssuerMetadata
    ) {
        return Mono.delay(Duration.ofSeconds(interval))
                .doOnNext(t -> System.out.println("✅ Delay completat després de " + interval + " segons"))
                .then(ensureValidToken(tokenInfo, tokenEndpoint))
                .flatMap(validTokenInfo ->
                        webClient.centralizedWebClient()
                                .post()
                                .uri(credentialIssuerMetadata.deferredCredentialEndpoint())
                                .contentType(MediaType.APPLICATION_JSON)
                                .header(HEADER_AUTHORIZATION, BEARER + validTokenInfo.accessToken())
                                .bodyValue(Map.of("transaction_id", transactionId))
                                .exchangeToMono(response -> {
                                    HttpStatusCode statusCode = response.statusCode();
                                    if (statusCode.is4xxClientError() || statusCode.is5xxServerError()) {
                                        return Mono.error(new RuntimeException(
                                                "Error during the deferred credential request, error: " + response
                                        ));
                                    } else {
                                        log.info("Deferred credential response retrieved, status: {}", statusCode);
                                        return response.bodyToMono(String.class)
                                                .flatMap(responseBody -> {
                                                    try {
                                                        log.debug("Deferred flow body: {}", responseBody);
                                                        CredentialResponse credentialResponse = objectMapper.readValue(responseBody, CredentialResponse.class);

                                                        if (credentialResponse.transactionId() != null
                                                                && credentialResponse.transactionId().equals(transactionId)) {
                                                            return handleDeferredCredential(
                                                                    validTokenInfo,
                                                                    tokenEndpoint,
                                                                    credentialResponse.transactionId(),
                                                                    credentialResponse.interval(),
                                                                    credentialIssuerMetadata
                                                            );
                                                        }

                                                        if (credentialResponse.credentials().get(0).credential() != null) {
                                                            log.debug("Deferred credential signature completed for: {}", transactionId);
                                                            return Mono.just(
                                                                    CredentialResponseWithStatus.builder()
                                                                            .credentialResponse(credentialResponse)
                                                                            .statusCode(statusCode)
                                                                            .build()
                                                            );
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
                                                });
                                    }
                                })
                )
                .doFirst(() -> log.debug("Starting deferred credential signature for: {}", transactionId));
    }

    private Mono<TokenInfo> ensureValidToken(TokenInfo tokenInfo, String tokenUrl) {
        System.out.println("HOLAAAA - valid token: token info : " + tokenInfo);
        long currentTime = Instant.now().getEpochSecond();
        System.out.println("HOLAAAA - current time : " + currentTime);
        long expiry = tokenInfo.tokenObtainedAt() + tokenInfo.expiresIn();
        System.out.println("HOLAAAA - tokenobtainedat : " + tokenInfo.tokenObtainedAt());
        System.out.println("HOLAAAA - tokenInfo.expiresIn : " + tokenInfo.expiresIn());
        System.out.println("HOLAAAA - expiriiiiyy : " + expiry);
        long safetyWindow = 10;

        boolean isAccessTokenValid = currentTime < (expiry - safetyWindow);
        System.out.println("L'access token és vàlid: " + isAccessTokenValid);
        if (isAccessTokenValid) {
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