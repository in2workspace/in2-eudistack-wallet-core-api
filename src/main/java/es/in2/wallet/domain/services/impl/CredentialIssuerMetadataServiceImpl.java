package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.ports.AppConfig;
import es.in2.wallet.domain.exceptions.FailedDeserializingException;
import es.in2.wallet.application.dto.CredentialIssuerMetadata;
import es.in2.wallet.application.dto.CredentialOffer;
import es.in2.wallet.domain.services.CredentialIssuerMetadataService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE;
import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE_APPLICATION_JSON;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialIssuerMetadataServiceImpl implements CredentialIssuerMetadataService {

    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;

    private final WebClientConfig webClient;

    @Override
    public Mono<CredentialIssuerMetadata> getCredentialIssuerMetadataFromCredentialOffer(String processId, CredentialOffer credentialOffer) {
        String credentialIssuerURL = credentialOffer.credentialIssuer() + "/.well-known/openid-credential-issuer";
        // get Credential Issuer Metadata
        return getCredentialIssuerMetadata(credentialIssuerURL)
                .doOnSuccess(response -> log.info("ProcessID: {} - Credential Issuer Metadata Response: {}", processId, response))
                .flatMap(this::parseCredentialIssuerMetadataResponse)
                .doOnNext(credentialIssuerMetadata -> log.info("ProcessID: {} - CredentialIssuerMetadata: {}", processId, credentialIssuerMetadata))
                .onErrorResume(e -> {
                    log.error("ProcessID: {} - Error while processing Credential Issuer Metadata from the Issuer: {}", processId, e.getMessage());
                    return Mono.error(new RuntimeException("Error while processing Credential Issuer Metadata from the Issuer"));
                });
    }

    private Mono<String> getCredentialIssuerMetadata(String credentialIssuerURL) {
        return webClient.centralizedWebClient()
                .get()
                .uri(credentialIssuerURL)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .exchangeToMono(response -> {
                    if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                        return Mono.error(new RuntimeException("Error while fetching Credential Issuer Metadata from the Issuer, error" + response));
                    }
                    else {
                        log.info("Credential issuer metadata: {}", response);
                        log.info("test");
                        return response.bodyToMono(String.class);
                    }
                });
    }

    /**
     * This method is marked as deprecated and will be replaced in the future.
     * The current implementation manually sets a specific field to maintain
     * backward compatibility with our wallet. Refactoring is planned to improve
     * this logic.
     *
     * @param response The response String to be parsed.
     * @return An instance of Mono<CredentialIssuerMetadata>.
     * @deprecated (since = " 1.0.0 ", forRemoval = true) This implementation is temporary and should be replaced in future versions.
     */
    @Deprecated(since = "1.0.0", forRemoval = true)
    private Mono<CredentialIssuerMetadata> parseCredentialIssuerMetadataResponse(String response) {
        try {
            JsonNode rootNode = objectMapper.readTree(response);
            if (rootNode.has("credential_token")) {
                CredentialIssuerMetadata credentialIssuerMetadataOriginal = objectMapper.treeToValue(rootNode, CredentialIssuerMetadata.class);
                CredentialIssuerMetadata credentialIssuerMetadataWithCredentialEndpointHardcoded = CredentialIssuerMetadata.builder()
                        .credentialIssuer(credentialIssuerMetadataOriginal.credentialIssuer())
                        .credentialEndpoint(credentialIssuerMetadataOriginal.credentialEndpoint())
                        .credentialsSupported(credentialIssuerMetadataOriginal.credentialsSupported())
                        .deferredCredentialEndpoint(credentialIssuerMetadataOriginal.deferredCredentialEndpoint())
                        .authorizationServer(appConfig.getAuthServerInternalUrl())
                        .build();
                return Mono.just(credentialIssuerMetadataWithCredentialEndpointHardcoded);
            } else {
                // deserialize Credential Issuer Metadata
                return Mono.just(objectMapper.readValue(response, CredentialIssuerMetadata.class));
            }

        } catch (Exception e) {
            return Mono.error(new FailedDeserializingException("Error while deserializing Credential Issuer Metadata: " + e));
        }
    }

}
