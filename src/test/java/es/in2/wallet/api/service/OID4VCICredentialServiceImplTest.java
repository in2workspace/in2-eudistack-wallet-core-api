package es.in2.wallet.api.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.domain.exceptions.FailedDeserializingException;
import es.in2.wallet.domain.exceptions.FailedSerializingException;
import es.in2.wallet.domain.services.impl.OID4VCICredentialServiceImpl;
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

import java.util.List;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OID4VCICredentialServiceImplTest {
    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WebClientConfig webClientConfig;
    @InjectMocks
    private OID4VCICredentialServiceImpl credentialService;

    @Test
    void getCredentialTest() throws JsonProcessingException {
        // GIVEN
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        // The service returns CredentialResponseWithStatus
        // We'll embed a CredentialResponse inside
        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("credential")
        );
        CredentialResponse mockCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        // Stubs for ObjectMapper
        when(objectMapper.writeValueAsString(any()))
                .thenReturn("credentialRequest");
        // When the service parses the server body -> parse as a CredentialResponse
        when(objectMapper.readValue(anyString(), eq(CredentialResponse.class)))
                .thenReturn(mockCredentialResponse);

        // Mock WebClient
        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        // Create a mock ClientResponse for a 200 OK
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("someRawBodyString")
                .build();

        // Stub the exchange function
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // WHEN
        Mono<CredentialResponseWithStatus> result = credentialService.getCredential(
                jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "VerifiableCredential"
        );

        // THEN
        StepVerifier.create(result)
                .expectNextMatches(actual ->
                        // Compare the fields you care about in 'actual'
                        actual.statusCode().equals(HttpStatus.OK)
                                && actual.credentialResponse().equals(mockCredentialResponse)
                )
                .verifyComplete();

    }

    @Test
    void getCredentialTestRuntimeException() throws JsonProcessingException {

        String jwt = "ey34324";

        TokenResponse tokenResponse = TokenResponse.builder().accessToken("token").build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder().credentialIssuer("issuer").credentialEndpoint("endpoint").build();


        when(objectMapper.writeValueAsString(any())).thenReturn("credentialRequest");

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        // Create a mock ClientResponse for a successful response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("error")
                .build();

        // Stub the exchange function to return the mock ClientResponse
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "VerifiableCredential"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void getCredentialTestWithoutTypes() throws JsonProcessingException {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("credential")
        );

        CredentialResponse mockCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        when(objectMapper.writeValueAsString(any()))
                .thenReturn("credentialRequest");
        when(objectMapper.readValue(anyString(), eq(CredentialResponse.class)))
                .thenReturn(mockCredentialResponse);

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("credential")
                .build();
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // The code returns Mono<CredentialResponseWithStatus>
        // We'll check it has our embedded CredentialResponse
        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "VerifiableCredential")
                )
                .expectNextMatches(actual ->
                        actual.credentialResponse().equals(mockCredentialResponse)
                                && actual.statusCode().equals(HttpStatus.OK)
                )
                .verifyComplete();
    }

    @Test
    void getCredentialTestForFiware() throws JsonProcessingException {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("credential")
        );

        CredentialResponse mockCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        when(objectMapper.writeValueAsString(any()))
                .thenReturn("credentialRequest");
        when(objectMapper.readValue(anyString(), eq(CredentialResponse.class)))
                .thenReturn(mockCredentialResponse);

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("credential")
                .build();
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "LEARCredential")
                )
                .expectNextMatches(actual ->
                        actual.credentialResponse().equals(mockCredentialResponse)
                                && actual.statusCode().equals(HttpStatus.OK)
                )
                .verifyComplete();
    }

    @Test
    void getCredentialTestWithoutProof_shouldReturnCredentialSuccessfully() throws JsonProcessingException {
        String jwt = null;
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("credential")
        );

        CredentialResponse mockCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        when(objectMapper.writeValueAsString(argThat(argument -> {
            if (!(argument instanceof CredentialRequest request)) return false;
            return request.proof() == null;
        }))).thenReturn("credentialRequest");

        when(objectMapper.readValue(anyString(), eq(CredentialResponse.class)))
                .thenReturn(mockCredentialResponse);

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("credential")
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "LEARCredential")
                )
                .expectNextMatches(actual ->
                        actual.credentialResponse().equals(mockCredentialResponse)
                                && actual.statusCode().equals(HttpStatus.OK)
                )
                .verifyComplete();
    }


    @Test
    void getCredentialFailedCommunicationErrorTest() throws JsonProcessingException {

        String jwt = "ey34324";

        TokenResponse tokenResponse = TokenResponse.builder().accessToken("token").build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder().credentialIssuer("issuer").credentialEndpoint("endpoint").build();

        when(objectMapper.writeValueAsString(any())).thenReturn("credentialRequest");

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        // Create a mock ClientResponse for a successful response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.BAD_REQUEST)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("error")
                .build();

        // Stub the exchange function to return the mock ClientResponse
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "LEARCredential"))
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void getCredentialFailedDeserializingErrorTest() throws JsonProcessingException {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialEndpoint("endpoint")
                .build();

        when(objectMapper.writeValueAsString(any()))
                .thenReturn("credentialRequest");
        // Force a parse error
        when(objectMapper.readValue(anyString(), eq(CredentialResponse.class)))
                .thenThrow(new JsonProcessingException("Deserialization error") {
                });

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("credential")
                .build();
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "LEARCredential")
                )
                .expectError(FailedDeserializingException.class)
                .verify();
    }

    @Test
    void getCredentialFailedSerializingExceptionTest() throws JsonProcessingException {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken("token")
                .build();

        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialEndpoint("endpoint")
                .build();

        // Force a serialization error
        when(objectMapper.writeValueAsString(any()))
                .thenThrow(new JsonProcessingException("Serialization error") {
                });

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, "LEARCredential")
                )
                .expectError(FailedSerializingException.class)
                .verify();
    }

    @Test
    void handleDeferredCredential_successfulResponse() throws Exception {
        String transactionId = "trans123";
        String endpoint = "https://issuer.org/deferred";

        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .deferredCredentialEndpoint(endpoint)
                .build();

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("mock-credential")
        );
        CredentialResponse mockResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .transactionId(transactionId)
                .build();

        String responseJson = "response-body";

        when(objectMapper.readValue(responseJson, CredentialResponse.class))
                .thenReturn(mockResponse);

        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(responseJson)
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.handleDeferredCredential(transactionId, metadata))
                .expectNextMatches(response ->
                        response.transactionId().equals(transactionId)
                                && response.credentials().get(0).credential().equals("mock-credential")
                )
                .verifyComplete();
    }

    @Test
    void handleDeferredCredential_missingCredentialAndNoNewTransactionId_shouldReturnError() throws Exception {
        String transactionId = "trans123";
        String endpoint = "https://issuer.org/deferred";

        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .deferredCredentialEndpoint(endpoint)
                .build();

        CredentialResponse incompleteResponse = CredentialResponse.builder()
                .transactionId(transactionId)
                .credentials(List.of(new CredentialResponse.Credentials(null)))
                .build();

        String responseJson = "incomplete-response";

        when(objectMapper.readValue(responseJson, CredentialResponse.class))
                .thenReturn(incompleteResponse);

        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(responseJson)
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.handleDeferredCredential(transactionId, metadata))
                .expectErrorMatches(error ->
                        error instanceof IllegalStateException &&
                                error.getMessage().contains("No credential or new transaction id received in deferred flow")
                )
                .verify();
    }

    @Test
    void handleDeferredCredential_deserializationFails_shouldReturnFailedDeserializingException() throws Exception {
        String transactionId = "trans123";
        String endpoint = "https://issuer.org/deferred";

        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .deferredCredentialEndpoint(endpoint)
                .build();

        String badJson = "bad-json-response";

        when(objectMapper.readValue(badJson, CredentialResponse.class))
                .thenThrow(new JsonProcessingException("Invalid JSON") {});

        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(badJson)
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.handleDeferredCredential(transactionId, metadata))
                .expectErrorMatches(error ->
                        error instanceof FailedDeserializingException &&
                                error.getMessage().contains("Error processing deferred CredentialResponse")
                )
                .verify();
    }

    @Test
    void handleDeferredCredential_recursiveCallOnNewTransactionId() throws Exception {
        String originalTransactionId = "trans123";
        String newTransactionId = "trans456";
        String endpoint = "https://issuer.org/deferred";

        CredentialIssuerMetadata metadata = CredentialIssuerMetadata.builder()
                .deferredCredentialEndpoint(endpoint)
                .build();

        CredentialResponse firstResponse = CredentialResponse.builder()
                .transactionId(newTransactionId)
                .credentials(List.of(new CredentialResponse.Credentials(null)))
                .build();

        CredentialResponse secondResponse = CredentialResponse.builder()
                .transactionId(newTransactionId)
                .credentials(List.of(new CredentialResponse.Credentials("final-credential")))
                .build();

        String firstJson = "first-response";
        String secondJson = "second-response";

        when(objectMapper.readValue(firstJson, CredentialResponse.class)).thenReturn(firstResponse);
        when(objectMapper.readValue(secondJson, CredentialResponse.class)).thenReturn(secondResponse);

        ClientResponse firstClientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(firstJson)
                .build();

        ClientResponse secondClientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(secondJson)
                .build();

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(firstClientResponse))
                .thenReturn(Mono.just(secondClientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);

        StepVerifier.create(credentialService.handleDeferredCredential(originalTransactionId, metadata))
                .expectNextMatches(response ->
                        response.transactionId().equals(newTransactionId) &&
                                response.credentials().get(0).credential().equals("final-credential")
                )
                .verifyComplete();
    }




    @Test
    void getCredentialDomeDeferredCaseTest() throws JsonProcessingException {
        String transactionId = "trans123";
        String accessToken = "access-token";
        String deferredEndpoint = "/deferred/endpoint";

        List<CredentialResponse.Credentials> credentialList = List.of(
                new CredentialResponse.Credentials("credentialData")
        );

        // We now expect to return a CredentialResponseWithStatus
        // with some embedded CredentialResponse + status code
        CredentialResponse expectedCredentialResponse = CredentialResponse.builder()
                .credentials(credentialList)
                .build();

        when(objectMapper.writeValueAsString(any())).thenReturn("credentialRequest");

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        // Suppose the server returns 200 OK with body "credential"
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("credential")
                .build();

        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
        when(webClientConfig.centralizedWebClient())
                .thenReturn(webClient);

        // The body "credential" -> parse into CredentialResponse
        when(objectMapper.readValue("credential", CredentialResponse.class))
                .thenReturn(expectedCredentialResponse);

        StepVerifier.create(
                        credentialService.getCredentialDomeDeferredCase(transactionId, accessToken, deferredEndpoint)
                )
                .expectNextMatches(crws ->
                        crws.statusCode().equals(HttpStatus.OK)
                                && crws.credentialResponse().equals(expectedCredentialResponse)
                )
                .verifyComplete();
    }

    @Test
    void getCredentialDomeDeferredCaseTestFailedDeserializingException() throws JsonProcessingException {
        String transactionId = "trans123";
        String accessToken = "access-token";
        String deferredEndpoint = "/deferred/endpoint";

        when(objectMapper.writeValueAsString(any())).thenReturn("credentialRequest");

        // Mock the response of the postCredential method
        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);

        // Create a mock ClientResponse for a successful response
        ClientResponse clientResponse = ClientResponse.create(HttpStatus.OK)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body("invalid body")
                .build();

        // Stub the exchange function to return the mock ClientResponse
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        when(webClientConfig.centralizedWebClient()).thenReturn(webClient);
        // Configure ObjectMapper to parse the mocked response
        when(objectMapper.readValue("invalid body", CredentialResponse.class))
                .thenThrow(new IllegalStateException("The response have a invalid format") {
                });

        // Execute the method and verify the results
        StepVerifier.create(credentialService.getCredentialDomeDeferredCase(transactionId, accessToken, deferredEndpoint))
                .expectError(FailedDeserializingException.class)
                .verify();
    }

    @Test
    void getCredential_throwsException_whenFormatNotSupported() {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder().accessToken("token").build();
        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        String unsupportedFormat = "ldp_vc";

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, unsupportedFormat, "SomeCredentialId")
                )
                .expectErrorMatches(error ->
                        error instanceof IllegalArgumentException &&
                                error.getMessage().contains("Format not supported")
                )
                .verify();
    }

    @Test
    void getCredential_throwsException_whenCredentialConfigurationIdIsNull() {
        String jwt = "ey34324";
        TokenResponse tokenResponse = TokenResponse.builder().accessToken("token").build();
        CredentialIssuerMetadata credentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("issuer")
                .credentialEndpoint("endpoint")
                .build();

        StepVerifier.create(
                        credentialService.getCredential(jwt, tokenResponse, credentialIssuerMetadata, JWT_VC_JSON, null)
                )
                .expectErrorMatches(error ->
                        error instanceof IllegalArgumentException &&
                                error.getMessage().contains("Credentials configurations ids not provided")
                )
                .verify();
    }






}
