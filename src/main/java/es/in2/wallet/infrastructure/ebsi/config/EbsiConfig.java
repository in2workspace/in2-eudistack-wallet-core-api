package es.in2.wallet.infrastructure.ebsi.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.ports.AppConfig;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.exceptions.NoSuchVerifiableCredentialException;
import es.in2.wallet.domain.services.CredentialService;
import es.in2.wallet.domain.services.DidKeyGeneratorService;
import es.in2.wallet.domain.services.UserService;
import es.in2.wallet.domain.utils.ApplicationUtils;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.wallet.domain.utils.ApplicationConstants.CONTENT_TYPE;
import static es.in2.wallet.domain.utils.ApplicationConstants.JWT_VC;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@Slf4j
@Component
@RequiredArgsConstructor
@Tag(name = "EbsiConfig", description = "Generate Did for Ebsi purposes")
public class EbsiConfig {

    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;
    private final DidKeyGeneratorService didKeyGeneratorService;
    private final UserService userService;
    private final CredentialService credentialService;
    private final WebClientConfig webClient;

    // We store the DID we generate (if any) in memory here
    private String didForEbsi;

    @PostConstruct
    public void onPostConstruct() {
        init()
                .subscribe(
                        unused -> log.info("EbsiConfig initialization completed"),
                        error -> log.error("Initialization failed", error)
                );
    }

    /**
     * Entry point for initialization.
     * - Retrieves a token from the identity provider.
     * - Extracts the userId from that token.
     * - Checks if a credential of type "ExampleCredential" already exists for that user.
     *    If so, we extract the DID from it.
     * - If not found, we generate a new DID and store a new credential so that
     *   we can pass EBSI test scenarios.
     *
     * @return Mono<String> with the final DID used/stored.
     */
    public Mono<String> init() {
        return generateEbsiDid()
                .doOnNext(did -> this.didForEbsi = did)
                .doOnError(error -> log.error("Initialization failed: {}", error.getMessage()));
    }

    /**
     * Returns the DID that was generated/stored during init().
     */
    public Mono<String> getDid() {
        return Mono.justOrEmpty(this.didForEbsi);
    }

    /**
     * Main logic for retrieving or creating a DID credential,
     * then returning the DID for EBSI usage.
     */
    private Mono<String> generateEbsiDid() {
        // Step 1: Build the body for the IDP token request
        String body = buildTokenRequestBody();

        // Step 2: Delay (15s) then request token
        return Mono.delay(Duration.ofSeconds(15))
                .then(
                        webClient.centralizedWebClient()
                                .post()
                                .uri(appConfig.getIdentityProviderUrl())
                                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                                .bodyValue(body)
                                .exchangeToMono(response -> {
                                    if (response.statusCode().isError()) {
                                        return Mono.error(new RuntimeException(
                                                "Error retrieving token for user: " + appConfig.getIdentityProviderUsername()
                                        ));
                                    } else {
                                        log.info("Token retrieval completed");
                                        return response.bodyToMono(String.class);
                                    }
                                })
                )
                // Step 3: Parse the token from JSON
                .flatMap(this::parseTokenFromResponse)
                // Step 4: Extract userId from token
                .flatMap(ApplicationUtils::getUserIdFromToken)
                // Step 5: Check if "ExampleCredential" already exists; if yes, retrieve DID; otherwise create
                .flatMap(this::findOrCreateDidCredential);
    }

    /**
     * Builds the body for retrieving a token from the identity provider.
     */
    private String buildTokenRequestBody() {
        String clientSecret = appConfig.getIdentityProviderClientSecret().trim();
        String decodedSecret;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(clientSecret);
            decodedSecret = new String(decodedBytes, StandardCharsets.UTF_8);
            String reEncoded = Base64.getEncoder().encodeToString(decodedSecret.getBytes(StandardCharsets.UTF_8)).trim();
            if (!clientSecret.equals(reEncoded)) {
                decodedSecret = clientSecret;
            }
        } catch (IllegalArgumentException ex) {
            decodedSecret = clientSecret;
        }
        return "grant_type=" + urlEncode("password") +
                "&username=" + urlEncode(appConfig.getIdentityProviderUsername()) +
                "&password=" + urlEncode(appConfig.getIdentityProviderPassword()) +
                "&client_id=" + urlEncode(appConfig.getIdentityProviderClientId()) +
                "&client_secret=" + urlEncode(decodedSecret);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Parse the token (as a String JSON) to extract "access_token" from the JSON response.
     */
    private Mono<String> parseTokenFromResponse(String jsonResponse) {
        log.debug("Token JSON response: {}", jsonResponse);
        try {
            Map<String, Object> jsonObject = objectMapper.readValue(jsonResponse, new TypeReference<>() {});
            if (jsonObject.containsKey("access_token")) {
                return Mono.just(jsonObject.get("access_token").toString());
            } else {
                return Mono.error(new RuntimeException("No 'access_token' field found in response"));
            }
        } catch (JsonProcessingException e) {
            return Mono.error(new RuntimeException("Error parsing token JSON", e));
        }
    }

    /**
     * Either finds an existing DID credential of the given type for the user
     * or creates a brand-new DID and credential if not found.
     */
    private Mono<String> findOrCreateDidCredential(String userId) {
        String processId = UUID.randomUUID().toString();

        // Try to fetch an existing credential for the user with the given type (in JWT_VC format)
        return credentialService.getCredentialsByUserIdAndType(processId, userId, "ExampleCredential")
                .flatMap(credentials -> {
                    // If we found some credential(s), extract the DID from the first
                    if (!credentials.isEmpty()) {
                        String firstCredId = credentials.get(0).id(); // the "id" field in CredentialsBasicInfo
                        return credentialService.extractDidFromCredential(processId, firstCredId, userId);
                    }
                    // If none found, generate new DID + create new credential
                    return createNewDidAndCredential(processId, userId);
                })
                // If no credentials exist, the above code moves to create them
                // If there's an error "NoSuchVerifiableCredentialException", we also create a new one
                .onErrorResume(NoSuchVerifiableCredentialException.class, ex -> {
                    log.info("No credential found for userId={}, type={}. Creating new DID...", userId, "ExampleCredential");
                    return createNewDidAndCredential(processId, userId);
                });
    }

    /**
     * Generates a brand-new DID and creates a credential referencing it.
     */
    private Mono<String> createNewDidAndCredential(String processId, String userId) {
        return generateDid()
                .flatMap(did -> createAndAddCredentialForEbsiTest(processId, userId, did)
                        .thenReturn(did)
                );
    }

    /**
     * Calls DidKeyGeneratorService to produce a DID.
     */
    private Mono<String> generateDid() {
        return didKeyGeneratorService.generateDidKeyJwkJcsPub();
    }

    /**
     * Creates a new user (if not exists) in the userRepositoryService,
     * then stores a new credential (with format=null => plain JSON).
     * The credential references the DID in its "credentialSubject.id".
     */
    private Mono<Void> createAndAddCredentialForEbsiTest(String processId, String userId, String did) {

        String credentialId = UUID.randomUUID().toString();
        String plainJsonVc = """
        {
          "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/extra"],
          "id": "%s",
          "type": ["VerifiableCredential", "ExampleCredential"],
          "credentialSubject": {
            "id": "%s"
          }
        }
        """
                .formatted(credentialId, did)
                .trim();

        // We'll store it as a plain credential (format=null => code checks "if format == null => parseAsPlainJson(...)")
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials(plainJsonVc)
        );

        CredentialResponse newCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .transactionId(UUID.randomUUID().toString())
                .build();

        return userService.storeUser(processId, userId)
                .flatMap(userUuid -> {
                    log.info("User {} stored with uuid={}", userId, userUuid);
                    return credentialService.saveCredential(processId, userUuid, newCredentialResponse, JWT_VC);
                })
                .doOnSuccess(savedCredId -> log.info("Created new credential {} for userId={}, with DID={}", savedCredId, userId, did))
                .then();
    }
}