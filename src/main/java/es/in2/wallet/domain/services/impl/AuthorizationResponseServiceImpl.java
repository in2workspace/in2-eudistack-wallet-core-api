package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.domain.exceptions.*;
import es.in2.wallet.domain.services.AuthorizationResponseService;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;


@Slf4j
@Service
@RequiredArgsConstructor

public class AuthorizationResponseServiceImpl implements AuthorizationResponseService {

    private final ObjectMapper objectMapper;

    private final WebClientConfig webClient;

    @Override
    public Mono<String> buildAndPostAuthorizationResponseWithVerifiablePresentation(String processId, VcSelectorResponse vcSelectorResponse, String verifiablePresentation, String authorizationToken) {
        log.info("Starting to build and post Authorization Response for processId: {}", processId);
        return generateDescriptorMapping(verifiablePresentation)
                .doOnSuccess(descriptorMapping -> log.debug("Successfully generated descriptor mapping for processId: {}", processId))
                .flatMap(descriptorMapping ->
                        getPresentationSubmissionAsString(processId, descriptorMapping))
                .doOnSuccess(submissionString -> log.debug("Successfully obtained Presentation Submission string for processId: {}", processId))
                .flatMap(presentationSubmissionString ->
                        postAuthorizationResponse(processId, vcSelectorResponse, verifiablePresentation,
                                presentationSubmissionString, authorizationToken))
                .doOnSuccess(response -> log.info("Successfully posted Authorization Response for processId: {}", processId))
                .doOnError(e -> log.warn("Error posting Authorization Response for processId: {}: {}", processId, e.getMessage()));
    }

    private Mono<DescriptorMap> generateDescriptorMapping(String verifiablePresentationString) {
        log.info("Starting to generate descriptor mapping for Verifiable Presentation.");
        // Parse the Verifiable Presentation
        return parseVerifiablePresentationFromString(verifiablePresentationString)
                .doOnSuccess(verifiablePresentation -> log.debug("Successfully parsed Verifiable Presentation: {}", verifiablePresentation))
                .flatMap(verifiablePresentation ->
                        // Process each Verifiable Credential in the Verifiable Presentation
                        Flux.fromIterable(Objects.requireNonNull(verifiablePresentation.verifiableCredential()))
                                .index()
                                .flatMap(indexed -> {
                                    String credential = indexed.getT2();
                                    Long index = indexed.getT1();
                                    return parseVerifiableCredentialFromString(credential)
                                            .map(verifiableCredential ->
                                                    new DescriptorMap(JWT_VC, "$.verifiableCredential[" + index + "]", verifiableCredential.id(), null)
                                            );
                                })
                                .collectList()  // Collect DescriptorMappings into a List
                                .flatMap(list -> buildDescriptorMapping(list, verifiablePresentation.id())) // Build the final DescriptorMapping
                );

    }

    private Mono<VerifiablePresentation> parseVerifiablePresentationFromString(String verifiablePresentationString) {
        log.debug("AuthorizationResponseServiceImpl -- parseVerifiablePresentationFromString -- Starting to parse Verifiable Presentation from string.");
        try {
            // Step 1: Decode the input string from Base64
            byte[] decodedBytes = Base64.getDecoder().decode(verifiablePresentationString);
            String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);

            // Step 2: Parse the decoded string as JWT
            JWT jwt = JWTParser.parse(decodedString);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

            // Step 3: Extract the "vp" claim and convert it into VerifiablePresentation
            JsonNode rootNode = objectMapper.valueToTree(claimsSet.getClaim("vp"));
            VerifiablePresentation verifiablePresentation = objectMapper.treeToValue(rootNode, VerifiablePresentation.class);

            log.debug("AuthorizationResponseServiceImpl -- parseVerifiablePresentationFromString -- Successfully parsed Verifiable Presentation from string.");
            return Mono.just(verifiablePresentation);
        } catch (ParseException e) {
            log.warn("ParseException -- parseVerifiablePresentationFromString -- Error while deserializing Verifiable Presentation: {}", e.getMessage());
            return Mono.error(new FailedDeserializingException("Error while deserializing Verifiable Presentation: " + e));
        } catch (IllegalArgumentException e) {
            log.warn("IllegalArgumentException -- parseVerifiablePresentationFromString -- Error decoding Verifiable Presentation from Base64: {}", e.getMessage());
            return Mono.error(new FailedDeserializingException("Error decoding Verifiable Presentation from Base64: " + e));
        } catch (JsonProcessingException e) {
            log.warn("JsonProcessingException -- parseVerifiablePresentationFromString -- Error serializing Verifiable Presentation:  {}", e.getMessage());
            return Mono.error(new FailedSerializingException("Error serializing Verifiable Presentation: " + e));
        }
    }


    private Mono<VerifiableCredential> parseVerifiableCredentialFromString(String verifiableCredentialString) {
        log.debug("AuthorizationResponseServiceImpl -- parseVerifiableCredentialFromString -- Starting to parse Verifiable Credential from string.");
        try {
            JWT jwt = JWTParser.parse(verifiableCredentialString);
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            JsonNode rootNode = objectMapper.valueToTree(claimsSet.getClaim("vc"));
            VerifiableCredential verifiableCredential = objectMapper.treeToValue(rootNode, VerifiableCredential.class);
            return Mono.just(verifiableCredential);
        } catch (ParseException e) {
            log.warn("ParseException -- parseVerifiableCredentialFromString -- Error while deserializing Verifiable Credential: {}", e.getMessage());
            return Mono.error(new FailedDeserializingException("Error deserializing Verifiable Credential"));
        } catch (JsonProcessingException e) {
            log.warn("JsonProcessingException -- parseVerifiableCredentialFromString -- Error while serializing Verifiable Credential: {}", e.getMessage());
            return Mono.error(new FailedSerializingException("Error serializing Verifiable Credential"));
        }
    }

    private Mono<DescriptorMap> buildDescriptorMapping(List<DescriptorMap> descriptorMappingList, String verifiablePresentationId) {
        log.debug("AuthorizationResponseServiceImpl -- buildDescriptorMapping -- Building Descriptor Mapping for Verifiable Presentation ID: {}", verifiablePresentationId);
        // Check if the list is empty
        if (descriptorMappingList == null || descriptorMappingList.isEmpty()) {
            log.warn("No DescriptorMappings found for Verifiable Presentation ID: {}", verifiablePresentationId);
            return Mono.empty();
        }
        // If the list has only one element, just return it
        Mono<DescriptorMap> result = Mono.just(descriptorMappingList.get(0));
        // If the list has more than one element, recursively add the DescriptorMappings
        for (int i = 1; i < descriptorMappingList.size(); i++) {
            DescriptorMap tmpCredentialDescriptorMap = descriptorMappingList.get(i);
            result = result.flatMap(credentialDescriptorMap ->
                    addCredentialDescriptorMap(credentialDescriptorMap, tmpCredentialDescriptorMap));
        }
        log.debug("AuthorizationResponseServiceImpl -- buildDescriptorMapping -- Successfully built Descriptor Mapping for Verifiable Presentation ID: {}", verifiablePresentationId);
        return result.map(finalMap -> new DescriptorMap(JWT_VP, "$", verifiablePresentationId, finalMap));
    }

    private Mono<String> getPresentationSubmissionAsString(String processId, DescriptorMap descriptorMapping) {
        log.debug("AuthorizationResponseServiceImpl -- getPresentationSubmissionAsString -- Generating PresentationSubmission as String for processId: {}", processId);
        return Mono.fromCallable(() -> {
                    PresentationSubmission presentationSubmission = new PresentationSubmission(
                            CUSTOMER_PRESENTATION_SUBMISSION,
                            CUSTOMER_PRESENTATION_DEFINITION,
                            Collections.singletonList(descriptorMapping)
                    );
                    return objectMapper.writeValueAsString(presentationSubmission);
                })
                .doOnSuccess(presentationSubmissionString ->
                        log.info("ProcessID: {} - PresentationSubmission: {}", processId, presentationSubmissionString))
                .onErrorResume(e -> {
                    log.warn("ProcessID: {} - Error parsing PresentationSubmission to String: {}", processId, e.getMessage());
                    return Mono.error(new RuntimeException("Error parsing PresentationSubmission", e));
                });
    }

    private Mono<DescriptorMap> addCredentialDescriptorMap(DescriptorMap credentialDescriptorMap, DescriptorMap tmpCredentialDescriptorMap) {
        // If the original DescriptorMapping is null, just return the temporary one
        if (credentialDescriptorMap == null) {
            return Mono.just(tmpCredentialDescriptorMap);
        }
        // If the pathNested of the original DescriptorMapping is null, create a new instance with the updated pathNested
        if (credentialDescriptorMap.pathNested() == null) {
            DescriptorMap updatedMap = new DescriptorMap(
                    credentialDescriptorMap.format(),
                    credentialDescriptorMap.path(),
                    credentialDescriptorMap.id(),
                    tmpCredentialDescriptorMap
            );
            return Mono.just(updatedMap);
        } else {
            // If pathNested is not null, recursively update pathNested
            return addCredentialDescriptorMap(credentialDescriptorMap.pathNested(), tmpCredentialDescriptorMap)
                    .map(updatedNestedMap -> new DescriptorMap(
                            credentialDescriptorMap.format(),
                            credentialDescriptorMap.path(),
                            credentialDescriptorMap.id(),
                            updatedNestedMap
                    ));
        }
    }

    private Mono<String> postAuthorizationResponse(String processId, VcSelectorResponse vcSelectorResponse,
                                                   String verifiablePresentation, String presentationSubmissionString, String authorizationToken) {
        log.info("Posting Authorization Response for processId: {}", processId);

        // Build URL encoded form data request body
        Map<String, String> formDataMap = Map.of(
                "state", vcSelectorResponse.state(),
                "vp_token", verifiablePresentation,
                "presentation_submission", presentationSubmissionString);
        // Build the request body
        String xWwwFormUrlencodedBody = formDataMap.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        // Post request
        return webClient.centralizedWebClient()
                .post()
                .uri(vcSelectorResponse.redirectUri())
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.AUTHORIZATION, BEARER + authorizationToken)
                .bodyValue(xWwwFormUrlencodedBody)
                .exchangeToMono(response -> {
                    System.out.println("XIVATO!: " + response.statusCode());
                    if (response.statusCode().is4xxClientError()) {
                        if (response.statusCode().value() == 401) {
                            log.warn("ProcessID: {} - Unauthorized, status: 401: Error: {}", processId, response);
                            return Mono.error(new AttestationUnauthorizedException("Attestation process returned an Unauthorized access error: " + response.statusCode()));
                        } else if(response.statusCode().value() == 403) {
                            log.warn("ProcessID: {} - Forbidden, status: 403: Error: {}", processId, response);
                            return Mono.error(new RevokedCredentialErrorException("Attestation process returned a Forbidden access error: " + response.statusCode()));
                        } else {
                            log.warn("ProcessID: {} - Client error, status: {}: Error: {}", processId, response.statusCode(), response);
                            return Mono.error(new AttestationClientErrorException("Attestation process returned a Client error: " + response.statusCode()));
                        }
                    } else if (response.statusCode().is5xxServerError()) {
                        log.error("ProcessID: {} - Server error, status: {}: Error: {}", processId, response.statusCode(), response);
                        return Mono.error(new AttestationServerErrorException("Attestation process returned a Server error: " + response.statusCode()));
                    } else if (response.statusCode().is3xxRedirection()) {
                        log.info("ProcessID: {} - Redirection to: {}", processId, response.headers().asHttpHeaders().getFirst(HttpHeaders.LOCATION));
                        return Mono.just(Objects.requireNonNull(response.headers().asHttpHeaders().getFirst(HttpHeaders.LOCATION)));
                    } else {
                        log.info("ProcessID: {} - Authorization Response: {}", processId, response);
                        return response.bodyToMono(String.class);
                    }
                });
    }

}
