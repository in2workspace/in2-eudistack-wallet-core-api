package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import es.in2.wallet.application.dto.*;
import es.in2.wallet.application.workflows.presentation.Oid4vpWorkflow;
import es.in2.wallet.domain.exceptions.FailedSerializingException;
import es.in2.wallet.domain.services.EbsiVpTokenService;
import es.in2.wallet.domain.services.PresentationService;
import es.in2.wallet.domain.utils.ApplicationUtils;
import es.in2.wallet.infrastructure.core.config.WebClientConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class EbsiVpTokenServiceImpl implements EbsiVpTokenService {
    private final ObjectMapper objectMapper;
    private final PresentationService presentationService;
    private final Oid4vpWorkflow oid4vpWorkflow;
    private final WebClientConfig webClient;
    /**
     * Initiates the process to exchange the authorization token and JWT for a VP Token Request,
     * logging the authorization response with the code upon success.
     *
     * @param processId An identifier for the process, used for logging.
     * @param authorizationToken The authorization token provided by the client.
     * @param authorisationServerMetadata Metadata about the authorisation server.
     * @param jwt The JWT that contains the presentation definition or a URI to it.
     */
    @Override
    public Mono<Map<String, String>> getVpRequest(String processId, String authorizationToken, AuthorisationServerMetadata authorisationServerMetadata, String jwt) {
        return completeVpTokenExchange(processId, authorizationToken, authorisationServerMetadata, jwt)
                .doOnSuccess(tokenResponse -> log.info("ProcessID: {} - Token Response: {}", processId, tokenResponse));
    }


    /**
     * Completes the VP Token exchange process by building a VP token response and extracting query parameters from it.
     */
    private Mono<Map<String, String>> completeVpTokenExchange(String processId, String authorizationToken, AuthorisationServerMetadata authorisationServerMetadata, String jwt) {
        return buildVpTokenResponse(processId,authorizationToken,jwt,authorisationServerMetadata)
                .flatMap(ApplicationUtils::extractAllQueryParams);
    }

    /**
     * Builds the VP Token response based on the JWT and authorization token, using the authorization server metadata.
     * This involves processing the presentation definition to understand the required credentials and constructing
     * the signed verifiable presentation and presentation submission accordingly.
     */
    private Mono<String> buildVpTokenResponse(String processId, String authorizationToken, String jwt, AuthorisationServerMetadata authorisationServerMetadata) {
        return extractRequiredParamFromJwt(jwt)
                .flatMap(params -> processPresentationDefinition(params.get(3))
                        .flatMap(map -> {
                            @SuppressWarnings("unchecked")
                            List<String> vcTypeList = (List<String>) map.get("types");
                            @SuppressWarnings("unchecked")
                            List<String> inputDescriptorIdsList = (List<String>) map.get("inputDescriptorIds");
                            String presentationDefinitionId = (String) map.get("presentationDefinitionId");

                            return buildSignedJwtVerifiablePresentationByVcTypeList(processId, authorizationToken, vcTypeList,params.get(0),authorisationServerMetadata)
                                    .flatMap(vp -> buildPresentationSubmission(inputDescriptorIdsList,presentationDefinitionId)
                                            .flatMap(presentationSubmission -> sendVpTokenResponse(vp,params,presentationSubmission))
                                    );
                        })
                );
    }
    /**
     * Sends the VP Token response to the redirect URI specified in the JWT, as an application/x-www-form-urlencoded payload.
     * This includes the VP token, presentation submission, and state parameters.
     */
    private Mono<String> sendVpTokenResponse(String vpToken, List<String> params, PresentationSubmission presentationSubmission) {
        try {
            String body = "vp_token=" + URLEncoder.encode(vpToken, StandardCharsets.UTF_8)
                    + "&presentation_submission=" + URLEncoder.encode(objectMapper.writeValueAsString(presentationSubmission), StandardCharsets.UTF_8)
                    + "&state=" + URLEncoder.encode(params.get(1), StandardCharsets.UTF_8);

            return webClient.centralizedWebClient()
                    .post()
                    .uri(params.get(2))
                    .header(CONTENT_TYPE, CONTENT_TYPE_URL_ENCODED_FORM)
                    .bodyValue(body)
                    .exchangeToMono(response -> {
                        if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                            return Mono.error(new RuntimeException("There was an error during the VP token response, error" + response));
                        } else {
                            return Mono.just(Objects.requireNonNull(response.headers().asHttpHeaders().getFirst(HttpHeaders.LOCATION)));
                        }
                    });
        }
        catch (JsonProcessingException e){
            return Mono.error(new FailedSerializingException("Error while serializing Presentation Submission"));
        }
    }

    /**
     * Builds a signed JWT Verifiable Presentation by extracting user data and credentials based on the VC type list provided.
     */
    private Mono<String> buildSignedJwtVerifiablePresentationByVcTypeList(String processId, String authorizationToken, List<String> vcTypeList, String nonce, AuthorisationServerMetadata authorisationServerMetadata) {
        return oid4vpWorkflow.getSelectableCredentialsRequiredToBuildThePresentation(processId,authorizationToken,vcTypeList)
                                        .collectList()
                                        .flatMap(list -> {
                                            log.debug(list.toString());
                                            VcSelectorResponse vcSelectorResponse = VcSelectorResponse.builder().selectedVcList(list).build();
                                            return presentationService.createSignedVerifiablePresentation(processId, authorizationToken, vcSelectorResponse, nonce, authorisationServerMetadata.issuer());
                                        });
    }

    private Mono<List<String>> extractRequiredParamFromJwt(String jwt) {
        try {
            log.debug(jwt);
            SignedJWT signedJwt = SignedJWT.parse(jwt);
            List<String> params = new ArrayList<>(List.of(
                    signedJwt.getJWTClaimsSet().getClaim("nonce").toString(),
                    signedJwt.getJWTClaimsSet().getClaim("state").toString(),
                    signedJwt.getJWTClaimsSet().getClaim("redirect_uri").toString())
            );

            if (signedJwt.getJWTClaimsSet().getClaim("presentation_definition") != null) {
                String presentationDefinition = objectMapper.writeValueAsString(signedJwt.getJWTClaimsSet().getClaim("presentation_definition"));
                params.add(presentationDefinition);
                return Mono.just(params);
            } else if (signedJwt.getJWTClaimsSet().getClaim("presentation_definition_uri") != null) {
                String presentationDefinitionUri = signedJwt.getJWTClaimsSet().getClaim("presentation_definition_uri").toString();
                return webClient.centralizedWebClient()
                        .get()
                        .uri(presentationDefinitionUri)
                        .exchangeToMono(response -> {
                            if (response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                                return Mono.error(new RuntimeException("There was an error retrieving presentation definition, error" + response));
                            }
                            else {
                                log.info("Presentation definition: {}", response);
                                return response.bodyToMono(String.class);
                            }
                        })
                        .flatMap(presentationDefinition -> {
                            try {
                                String presentationDefinitionStr = objectMapper.writeValueAsString(presentationDefinition);
                                params.add(presentationDefinitionStr);
                                return Mono.just(params);
                            }catch (JsonProcessingException e){
                                return Mono.error(new IllegalArgumentException("Error getting property"));
                            }

                        });
            } else {
                throw new IllegalArgumentException("not known property");
            }
        } catch (ParseException | JsonProcessingException e) {
            return Mono.error(new IllegalArgumentException("Error getting property"));
        }
    }

    /**
     * Processes a JSON string representing a Presentation Definition into a map containing relevant properties.
     * This method deserializes the JSON string into a PresentationDefinition object, extracts and collects
     * specific attributes like presentation definition ID, types, and input descriptor IDs into a map for
     * further processing or use.
     *
     * @param jsonDefinition The JSON string representation of a Presentation Definition.
     */
    private Mono<Map<String, Object>> processPresentationDefinition(String jsonDefinition) {
        return Mono.fromCallable(() -> {
            PresentationDefinition definition = objectMapper.readValue(jsonDefinition, PresentationDefinition.class);
            Map<String, Object> propertiesMap = new HashMap<>();

            propertiesMap.put("presentationDefinitionId", definition.id());
            propertiesMap.put("types", extractTypes(definition));
            propertiesMap.put("inputDescriptorIds", extractInputDescriptorIds(definition));

            return propertiesMap;
        });
    }

    /**
     * Extracts types specified within the constraints of input descriptors from a Presentation Definition.
     * It navigates through each input descriptor and its fields to find and collect the 'const' values specified
     * in the 'contains' filter, which represent the types of credentials required by the presentation.
     *
     * @param definition The Presentation Definition object to extract types from.
     */
    private List<String> extractTypes(PresentationDefinition definition) {
        List<String> typesList = new ArrayList<>();
        for (PresentationDefinition.InputDescriptor descriptor : definition.inputDescriptors()) {
            for (PresentationDefinition.InputDescriptor.Constraint.Field field : descriptor.constraints().fields()) {
                JsonNode constNode = findConstNode(field);
                if (constNode != null) {
                    typesList.add(constNode.asText());
                }
            }
        }
        return typesList;
    }

    /**
     * Finds and returns the 'const' node from a field's filter if it exists.
     * This helper method looks for a 'const' node within a 'contains' node in the filter definition
     * of a field within an input descriptor's constraints. It is used to identify the specific types
     * required by the input descriptor.
     *
     * @param field The field object to search the 'const' node in.
     */
    private JsonNode findConstNode(PresentationDefinition.InputDescriptor.Constraint.Field field) {
        JsonNode filterNode = field.filter();
        if (filterNode != null && filterNode.isObject()) {
            JsonNode containsNode = filterNode.path("contains");
            if (!containsNode.isMissingNode() && containsNode.isObject()) {
                JsonNode constNode = containsNode.path("const");
                if (!constNode.isMissingNode() && constNode.isTextual()) {
                    return constNode;
                }
            }
        }
        return null;
    }

    /**
     * Extracts the IDs of input descriptors from a Presentation Definition.
     * This method iterates through each input descriptor of the definition and collects their IDs.
     *
     * @param definition The Presentation Definition object to extract input descriptor IDs from.
     */
    private List<String> extractInputDescriptorIds(PresentationDefinition definition) {
        List<String> inputDescriptorIds = new ArrayList<>();
        for (PresentationDefinition.InputDescriptor descriptor : definition.inputDescriptors()) {
            inputDescriptorIds.add(descriptor.id());
        }
        return inputDescriptorIds;
    }

    /**
     * Builds a Presentation Submission object based on the given IDs and presentation definition ID.
     * This method constructs a Presentation Submission object with a dynamically created list of descriptor maps.
     * Each descriptor map corresponds to an input descriptor identified by the given IDs, with nested descriptor maps
     * specifying the path to locate the verifiable credential within the presentation.
     *
     * @param ids The list of input descriptor IDs to include in the presentation submission.
     * @param presentationDefinitionId The ID of the presentation definition that this submission relates to.
     */
    private Mono<PresentationSubmission> buildPresentationSubmission(List<String> ids, String presentationDefinitionId) {
        List<DescriptorMap> descriptorMaps = new ArrayList<>();

        for (int i = 0; i < ids.size(); i++) {
            String id = ids.get(i);
            DescriptorMap nestedDescriptorMap = DescriptorMap.builder()
                    .id(id)
                    .format(JWT_VC)
                    .path("$.vp.verifiableCredential[" + i + "]")
                    .pathNested(null).build();

            DescriptorMap descriptorMap = DescriptorMap.builder()
                    .id(id)
                    .format(JWT_VP)
                    .path("$")
                    .pathNested(nestedDescriptorMap).build();

            descriptorMaps.add(descriptorMap);
        }

        return Mono.just(PresentationSubmission.builder()
                .id(UUID.randomUUID().toString())
                .definitionId(presentationDefinitionId)
                .descriptorMap(descriptorMaps).build());
    }
}
