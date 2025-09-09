package es.in2.wallet.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.CredentialOffer;
import es.in2.wallet.domain.services.impl.CredentialOfferServiceImpl;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferServiceImplTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WebClientConfig webClientConfig;

    @InjectMocks
    private CredentialOfferServiceImpl credentialOfferService;


    @Test
    void testGetCredentialOfferFromCredentialOfferUriWhenTheresNoCredentialsNode_Success() throws Exception {
        String processId = "123";
        String credentialOfferUri = "openid://?credential_offer=https://example.com/offer";
        CredentialOffer expectedCredentialOffer = CredentialOffer
                .builder()
                .credentialConfigurationsIds(Set.of("UniversityDegreeCredential"))
                .credentialIssuer("https://credential-issuer.example.com")
                .grant(CredentialOffer.Grant.builder()
                        .preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder()
                                .preAuthorizedCode("oaKazRN8I0IbtZ0C7JuMn5")
                                .txCode(CredentialOffer.Grant.PreAuthorizedCodeGrant.TxCode.builder()
                                        .length(4)
                                        .inputMode("numeric")
                                        .description("Please provide the one-time code that was sent via e-mail")
                                        .build())
                                .build())
                        .build())
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        String credentialOfferJsonNode = """
                {
                   "credential_issuer": "https://credential-issuer.example.com",
                   "credential_configuration_ids": [
                      "UniversityDegreeCredential"
                   ],
                   "grants": {
                      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                         "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                         "tx_code": {
                            "length": 4,
                            "input_mode": "numeric",
                            "description": "Please provide the one-time code that was sent via e-mail"
                         }
                      }
                   }
                }
                """;

        // Create a mock ClientResponse for a successful response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json")
                .body("credential offer")
                .build();

        // Stub the exchange function to return the mock ClientResponse
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        ObjectMapper objectMapper1 = new ObjectMapper();
        JsonNode jsonNode = objectMapper1.readTree(credentialOfferJsonNode);
        when(objectMapper.readTree("credential offer")).thenReturn(jsonNode);
        when(objectMapper.treeToValue(any(JsonNode.class), any(Class.class))).thenReturn(expectedCredentialOffer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectNext(expectedCredentialOffer)
                .verifyComplete();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUriWhenCredentialOfferUriIsParsed_Success() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";
        CredentialOffer expectedCredentialOffer = CredentialOffer
                .builder()
                .credentialConfigurationsIds(Set.of("UniversityDegreeCredential"))
                .credentialIssuer("https://credential-issuer.example.com")
                .grant(CredentialOffer.Grant.builder()
                        .preAuthorizedCodeGrant(CredentialOffer.Grant.PreAuthorizedCodeGrant.builder()
                                .preAuthorizedCode("oaKazRN8I0IbtZ0C7JuMn5")
                                .txCode(CredentialOffer.Grant.PreAuthorizedCodeGrant.TxCode.builder()
                                        .length(4)
                                        .inputMode("numeric")
                                        .description("Please provide the one-time code that was sent via e-mail")
                                        .build())
                                .build())
                        .build())
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        String credentialOfferJsonNode = """
                {
                   "credential_issuer": "https://credential-issuer.example.com",
                   "credential_configuration_ids": [
                      "UniversityDegreeCredential"
                   ],
                   "grants": {
                      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                         "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
                         "tx_code": {
                            "length": 4,
                            "input_mode": "numeric",
                            "description": "Please provide the one-time code that was sent via e-mail"
                         }
                      }
                   }
                }
                """;

        // Create a mock ClientResponse for a successful response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header("Content-Type", "application/json")
                .body("credential offer")
                .build();

        // Stub the exchange function to return the mock ClientResponse
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        ObjectMapper objectMapper1 = new ObjectMapper();
        JsonNode jsonNode = objectMapper1.readTree(credentialOfferJsonNode);
        when(objectMapper.readTree("credential offer")).thenReturn(jsonNode);
        when(objectMapper.treeToValue(any(JsonNode.class), any(Class.class))).thenReturn(expectedCredentialOffer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectNext(expectedCredentialOffer)
                .verifyComplete();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUri_ThrowsIllegalArgumentException_WhenCredentialIssuerMissing() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";
        CredentialOffer offer = CredentialOffer.builder()
                .credentialConfigurationsIds(Set.of("id"))
                .grant(CredentialOffer.Grant.builder().build())
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(WebClient.builder().exchangeFunction(clientRequest ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("credential offer").build())
        ).build());

        when(objectMapper.readTree("credential offer")).thenReturn(mock(JsonNode.class));
        when(objectMapper.treeToValue(any(JsonNode.class), eq(CredentialOffer.class))).thenReturn(offer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectErrorMatches(throwable -> throwable instanceof IllegalArgumentException &&
                        throwable.getMessage().equals("Missing required field: credentialIssuer"))
                .verify();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUri_ThrowsIllegalArgumentException_WhenCredentialConfigurationIdsMissing() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";
        CredentialOffer offer = CredentialOffer.builder()
                .credentialIssuer("https://issuer.example.com")
                .grant(CredentialOffer.Grant.builder().build())
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(WebClient.builder().exchangeFunction(clientRequest ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("credential offer").build())
        ).build());

        when(objectMapper.readTree("credential offer")).thenReturn(mock(JsonNode.class));
        when(objectMapper.treeToValue(any(JsonNode.class), eq(CredentialOffer.class))).thenReturn(offer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectErrorMatches(throwable -> throwable instanceof IllegalArgumentException &&
                        throwable.getMessage().equals("Missing required field: credentialConfigurationIds"))
                .verify();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUri_ThrowsIllegalArgumentException_WhenCredentialIssuerIsBlank() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";

        when(webClientConfig.centralizedWebClient()).thenReturn(WebClient.builder().exchangeFunction(clientRequest ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("credential offer").build())
        ).build());

        JsonNode mockJsonNode = mock(JsonNode.class);
        when(objectMapper.readTree("credential offer")).thenReturn(mockJsonNode);

        CredentialOffer credentialOffer = CredentialOffer.builder()
                .credentialIssuer("") // está en blanco
                .credentialConfigurationsIds(Set.of("valid-id"))
                .grant(CredentialOffer.Grant.builder().build())
                .build();

        when(objectMapper.treeToValue(mockJsonNode, CredentialOffer.class)).thenReturn(credentialOffer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().equals("Missing required field: credentialIssuer"))
                .verify();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUri_ThrowsIllegalArgumentException_WhenCredentialConfigurationsIdsIsEmpty() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";

        when(webClientConfig.centralizedWebClient()).thenReturn(WebClient.builder().exchangeFunction(clientRequest ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("credential offer").build())
        ).build());

        JsonNode mockJsonNode = mock(JsonNode.class);
        when(objectMapper.readTree("credential offer")).thenReturn(mockJsonNode);

        CredentialOffer credentialOffer = CredentialOffer.builder()
                .credentialIssuer("https://valid-issuer.com")
                .credentialConfigurationsIds(Set.of()) // vacío
                .grant(CredentialOffer.Grant.builder().build())
                .build();

        when(objectMapper.treeToValue(mockJsonNode, CredentialOffer.class)).thenReturn(credentialOffer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().equals("Missing required field: credentialConfigurationIds"))
                .verify();
    }

    @Test
    void testGetCredentialOfferFromCredentialOfferUri_ThrowsIllegalArgumentException_WhenGrantMissing() throws JsonProcessingException {
        String processId = "123";
        String credentialOfferUri = "https://example.com/offer";
        CredentialOffer offer = CredentialOffer.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialConfigurationsIds(Set.of("id"))
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(WebClient.builder().exchangeFunction(clientRequest ->
                Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body("credential offer").build())
        ).build());

        when(objectMapper.readTree("credential offer")).thenReturn(mock(JsonNode.class));
        when(objectMapper.treeToValue(any(JsonNode.class), eq(CredentialOffer.class))).thenReturn(offer);

        StepVerifier.create(credentialOfferService.getCredentialOfferFromCredentialOfferUri(processId, credentialOfferUri))
                .expectErrorMatches(throwable -> throwable instanceof IllegalArgumentException &&
                        throwable.getMessage().equals("Missing required field: grant"))
                .verify();
    }

}
