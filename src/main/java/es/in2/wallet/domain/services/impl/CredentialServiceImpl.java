package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBORObject;
import es.in2.wallet.application.dto.CredentialEntityBuildParams;
import es.in2.wallet.application.dto.CredentialResponse;
import es.in2.wallet.application.dto.CredentialStatus;
import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.domain.entities.Credential;
import es.in2.wallet.domain.enums.CredentialFormats;
import es.in2.wallet.domain.enums.LifeCycleStatus;
import es.in2.wallet.domain.exceptions.NoSuchVerifiableCredentialException;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.domain.repositories.CredentialRepository;
import es.in2.wallet.domain.services.CredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.minvws.encoding.Base45;
import org.apache.commons.compress.compressors.CompressorInputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.*;
import java.util.stream.StreamSupport;

import static es.in2.wallet.domain.utils.ApplicationConstants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialServiceImpl implements CredentialService {

    private final CredentialRepository credentialRepository;
    private final ObjectMapper objectMapper;

    // ---------------------------------------------------------------------
    // Save Credential
    // ---------------------------------------------------------------------
    @Override
    public Mono<String> saveCredential(String processId, UUID userId, CredentialResponse credentialResponse, String format) {
        Instant currentTime = Instant.now();

        if (credentialResponse == null) {
            return Mono.error(new IllegalArgumentException("CredentialResponse is null"));
        }

        // If transactionId is present, treat it as a plain (non-signed) credential
        if (credentialResponse.transactionId() != null) {
            return extractCredentialFormat(format)
                    .flatMap(credentialFormat ->
                            parseAsPlainJson(credentialResponse.credentials().get(0).credential())
                                    .flatMap(vcJson -> Mono.zip(
                                            extractCredentialTypes(vcJson),
                                            extractVerifiableCredentialIdFromVcJson(vcJson),
                                            (types, credentialId) -> buildCredentialEntity(
                                                    CredentialEntityBuildParams.builder()
                                                            .credentialId(credentialId)
                                                            .userId(userId)
                                                            .credentialTypes(types)
                                                            .credentialFormat(credentialFormat)
                                                            .credentialData(null)
                                                            .vcJson(vcJson)
                                                            .lifeCycleStatus(LifeCycleStatus.ISSUED)  // Deferred => ISSUED
                                                            .currentTime(currentTime)
                                                            .build()
                                            )
                                    ))
                    )
                    .flatMap(credentialEntity ->
                            credentialRepository.save(credentialEntity)
                                    .doOnSuccess(saved -> log.info(
                                            "[Process ID: {}] Deferred credential with ID {} saved successfully.",
                                            processId,
                                            saved.getCredentialId()
                                    ))
                                    .thenReturn(credentialEntity.getCredentialId())
                    );
        }

        // Otherwise, handle known formats (JWT_VC, CWT_VC)
        return extractCredentialFormat(format)
                .flatMap(credentialFormat ->
                        extractVcJson(credentialResponse, format)
                                .flatMap(vcJson -> Mono.zip(
                                        extractCredentialTypes(vcJson),
                                        extractVerifiableCredentialIdFromVcJson(vcJson),
                                        (credentialTypes, credentialId) -> buildCredentialEntity(
                                                CredentialEntityBuildParams.builder()
                                                        .credentialId(credentialId)
                                                        .userId(userId)
                                                        .credentialTypes(credentialTypes)
                                                        .credentialFormat(credentialFormat)
                                                        .credentialData(credentialResponse.credentials().get(0).credential()) // raw credential data
                                                        .vcJson(vcJson)
                                                        .lifeCycleStatus(LifeCycleStatus.VALID) // store as VALID code
                                                        .currentTime(currentTime)
                                                        .build()
                                        )
                                ))
                                .flatMap(credentialEntity ->

                                        credentialRepository.save(credentialEntity)
                                                .doOnSuccess(saved -> log.info(
                                                        "[Process ID: {}] Credential with ID {} saved successfully.",
                                                        processId,
                                                        saved.getCredentialId()
                                                ))
                                                .thenReturn(credentialEntity.getCredentialId())
                                )
                );
    }


    // ---------------------------------------------------------------------
    // Deferred Credential
    // ---------------------------------------------------------------------
    @Override
    public Mono<Void> saveDeferredCredential(
            String processId,
            String userId,
            String credentialId,
            CredentialResponse credentialResponse
    ) {
        return parseStringToUuid(userId, USER_ID)
                .zipWith(Mono.just(credentialId))
                .flatMap(tuple -> {
                    UUID userUuid = tuple.getT1();
                    String credentialIdFromTuple  = tuple.getT2();
                    // We need to ensure the credential is in ISSUED status
                    return fetchCredentialOrErrorInIssuedStatus(credentialIdFromTuple  , userUuid);
                })
                .flatMap(existingCredential -> updateCredentialEntity(existingCredential, credentialResponse))
                .doOnSuccess(updatedEntity ->
                        log.info("[Process ID: {}] Deferred credential {} updated to VALID for user {}",
                                processId, updatedEntity.getCredentialId(), userId)
                )
                .then()
                .doOnError(error ->
                        log.error("[Process ID: {}] Error saving deferred credential ID {}: {}",
                                processId, credentialId, error.getMessage(), error)
                );
    }

    // ---------------------------------------------------------------------
    // Fetch All Credentials
    // ---------------------------------------------------------------------
    @Override
    public Mono<List<Credential>> getAllCredentials() {
        return credentialRepository.findAll()
                .collectList()
                .flatMap(list -> {
                    if (list.isEmpty()) {
                        return Mono.error(new NoSuchVerifiableCredentialException(
                                "No credentials found"));
                    }
                    return Mono.just(list);
                });
    }

    @Override
    public CredentialStatus getCredentialStatus(Credential credential){
        JsonNode jsonVc = getCredentialJsonVc(credential);
        return Optional.ofNullable(jsonVc.get("credentialStatus"))
                .filter(node -> !node.isNull())
                .map(this::mapToCredentialStatus)
                .orElse(null);
    }

    @Override
    public JsonNode getCredentialJsonVc(Credential credential){
        return parseJsonVc(credential.getJsonVc());
    }


    // ---------------------------------------------------------------------
    // Fetch All Credentials by User
    // ---------------------------------------------------------------------
    @Override
    public Mono<List<VerifiableCredential>> getCredentialsByUserId(String processId, String userId) {
        return parseStringToUuid(userId, USER_ID)
                .flatMapMany(credentialRepository::findAllByUserId)
                .flatMap(credential -> {
                    try {
                        return Mono.just(mapToVerifiableCredential(credential));
                    } catch (Exception e) {
                        log.warn("[{}] Error mapping credential {} for user {}",
                                processId, credential.getCredentialId(), userId, e);
                        return Mono.empty();
                    }
                })
                .collectList()
                .flatMap(list -> list.isEmpty()
                        ? Mono.error(new NoSuchVerifiableCredentialException(
                        "The credentials list is empty. Cannot proceed." + userId))
                        : Mono.just(list));
    }

    // ---------------------------------------------------------------------
    // Helper to map from Credential entity to DTO
    // ---------------------------------------------------------------------
    private VerifiableCredential mapToVerifiableCredential(Credential credential) {
        JsonNode jsonVc = getCredentialJsonVc(credential);

        JsonNode contextNode = jsonVc.get("@context");
        List<String> context = StreamSupport.stream(contextNode.spliterator(), false)
                .map(JsonNode::asText)
                .toList();

        JsonNode credentialSubject = jsonVc.get("credentialSubject");

        String name = Optional.ofNullable(credentialSubject.get("name"))
                .map(JsonNode::asText)
                .orElse("");

        String description = Optional.ofNullable(credentialSubject.get("description"))
                .map(JsonNode::asText)
                .orElse("");

        JsonNode issuer = Optional.ofNullable(jsonVc.get("issuer")).orElse(objectMapper.createObjectNode());

        String validUntil = Optional.ofNullable(jsonVc.get("validUntil"))
                .map(JsonNode::asText)
                .orElse("");

        String validFrom = Optional.ofNullable(jsonVc.get("validFrom"))
                .map(JsonNode::asText)
                .orElse("");

        CredentialStatus credentialStatus = Optional.ofNullable(jsonVc.get("credentialStatus"))
                .filter(node -> !node.isNull())
                .map(this::mapToCredentialStatus)
                .orElse(null);

        return VerifiableCredential.builder()
                .context(context)
                .id(credential.getCredentialId())
                .type(credential.getCredentialType())
                .lifeCycleStatus(credential.getCredentialStatus())
                .name(name)
                .description(description)
                .issuer(issuer)
                .validUntil(validUntil)
                .validFrom(validFrom)
                .credentialSubject(credentialSubject)
                .credentialStatus(credentialStatus)
                .build();
    }

    private CredentialStatus mapToCredentialStatus(JsonNode credentialStatusNode) {
        return CredentialStatus.builder()
                .id(credentialStatusNode.get("id").asText())
                .type(credentialStatusNode.get("type").asText())
                .statusPurpose(credentialStatusNode.get("statusPurpose").asText())
                .statusListIndex(credentialStatusNode.get("statusListIndex").asText())
                .statusListCredential(credentialStatusNode.get("statusListCredential").asText())
                .build();
    }



    // ---------------------------------------------------------------------
    // Filter credentials by user AND type in JWT_VC format
    // ---------------------------------------------------------------------
    @Override
    // TODO: Refactor this method to return Flux<VerifiableCredential> instead of Mono<List<VerifiableCredential>>
    public Mono<List<VerifiableCredential>> getCredentialsByUserIdAndType(
            String processId,
            String userId,
            String requiredType
    ) {
        return parseStringToUuid(userId, USER_ID)
                .flatMapMany(credentialRepository::findAllByUserId)
                .filter(credential -> {
                    boolean matchesType = credential.getCredentialType().contains(requiredType);
                    boolean isJwtVc = credential.getCredentialFormat() != null
                            && credential.getCredentialFormat().equals(CredentialFormats.JWT_VC.toString());
                    return matchesType && isJwtVc;
                })
                .flatMap(credential -> {
                    try {
                        return Mono.just(mapToVerifiableCredential(credential));
                    } catch (Exception e) {
                        log.warn("[{}] Error mapping credential {} for user {}",
                                processId, credential.getCredentialId(), userId, e);
                        return Mono.empty();
                    }
                })
                .collectList()
                .flatMap(credentialsInfo -> {
                    if (credentialsInfo.isEmpty()) {
                        return Mono.error(new NoSuchVerifiableCredentialException(
                                "No credentials found for userId=" + userId
                                        + " with type=" + requiredType
                                        + " in JWT_VC format."
                        ));
                    }
                    return Mono.just(credentialsInfo);
                });
    }

    // ---------------------------------------------------------------------
    // Return raw credential data (checked ownership)
    // ---------------------------------------------------------------------
    @Override
    public Mono<String> getCredentialDataByIdAndUserId(
            String processId,
            String userId,
            String credentialId
    ) {
        return parseStringToUuid(userId, USER_ID)
                .zipWith(Mono.just(credentialId))
                .flatMap(tuple -> {
                    UUID userUuid = tuple.getT1();
                    String credentialIdFromTuple = tuple.getT2();
                    return fetchCredentialOrError(credentialIdFromTuple, userUuid);  // no special status required
                })
                .map(credential -> {
                    String data = credential.getCredentialData();
                    log.info("[Process ID: {}] Successfully retrieved credential data for credentialId={}, userId={}",
                            processId, credential.getCredentialId(), userId);
                    return data;
                });
    }

    // ---------------------------------------------------------------------
    // Extract DID
    // ---------------------------------------------------------------------
    @Override
    public Mono<String> extractDidFromCredential(String processId, String credentialId, String userId) {
        return parseStringToUuid(userId, USER_ID)
                .zipWith(Mono.just(credentialId))
                .flatMap(tuple -> {
                    UUID userUuid = tuple.getT1();
                    String credentialIdFromTuple = tuple.getT2();
                    return fetchCredentialOrError(credentialIdFromTuple, userUuid);
                })
                .flatMap(credential -> {
                    // Parse the VC JSON
                    JsonNode vcNode = getCredentialJsonVc(credential);

                    // Decide if LEARCredentialEmployee
                    boolean isLear = credential.getCredentialType().stream()
                            .anyMatch("LEARCredentialEmployee"::equals);

                    // Extract DID from the correct path
                    JsonNode didNode = isLear
                            ? vcNode.at("/credentialSubject/mandate/mandatee/id")
                            : vcNode.at("/credentialSubject/id");

                    if (didNode.isMissingNode() || didNode.asText().isBlank()) {
                        return Mono.error(new NoSuchVerifiableCredentialException("DID not found in credential"));
                    }
                    return Mono.just(didNode.asText());
                });
    }

    // ---------------------------------------------------------------------
    // Delete credential
    // ---------------------------------------------------------------------
    @Override
    public Mono<Void> deleteCredential(String processId, String credentialId, String userId) {
        return parseStringToUuid(userId, USER_ID)
                .zipWith(Mono.just(credentialId))
                .flatMap(tuple -> {
                    UUID userUuid = tuple.getT1();
                    String credentialIdFromTuple = tuple.getT2();
                    return fetchCredentialOrError(credentialIdFromTuple, userUuid);
                })
                .flatMap(credentialRepository::delete)
                .doOnSuccess(unused ->
                        log.info("[Process ID: {}] Credential with ID {} successfully deleted for user {}",
                                processId, credentialId, userId)
                );
    }

    // ---------------------------------------------------------------------
    // Update Credential Life Cycle to REVOKE
    // ---------------------------------------------------------------------
    @Override
    public Mono<Credential> updateCredentialEntityLifeCycleStatus(Credential existingCredential, LifeCycleStatus lifeCycleStatus) {
        existingCredential.setCredentialStatus(lifeCycleStatus.toString());
        existingCredential.setUpdatedAt(Instant.now());
        return credentialRepository.save(existingCredential);
    }

    // ---------------------------------------------------------------------
    // Private Helper to fetch credential from DB and check ownership
    // (optionally can also check status)
    // ---------------------------------------------------------------------
    private Mono<Credential> fetchCredentialOrError(String credentialId, UUID userId) {
        // No status check
        return credentialRepository.findByCredentialId(credentialId)
                .switchIfEmpty(Mono.error(new NoSuchVerifiableCredentialException(
                        "No credential found for ID: " + credentialId
                )))
                .flatMap(credential -> {
                    if (!credential.getUserId().equals(userId)) {
                        return Mono.error(new IllegalStateException(
                                "User ID mismatch. Credential belongs to user " + credential.getUserId()
                        ));
                    }
                    return Mono.just(credential);
                });
    }

    private Mono<Credential> fetchCredentialOrErrorInIssuedStatus(String credentialId, UUID userId) {
        return fetchCredentialOrError(credentialId, userId)
                .flatMap(credential -> {
                    if (!Objects.equals(credential.getCredentialStatus(), LifeCycleStatus.ISSUED.toString())) {
                        return Mono.error(new IllegalStateException(
                                "Credential is not in ISSUED status (found " + credential.getCredentialStatus() + ")"
                        ));
                    }
                    return Mono.just(credential);
                });
    }


    // ---------------------------------------------------------------------
    // Parsing Helpers
    // ---------------------------------------------------------------------
    private Mono<UUID> parseStringToUuid(String value, String fieldName) {
        return Mono.fromCallable(() -> {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(fieldName + " is null or blank");
            }
            return UUID.fromString(value);
        });
    }

    // ---------------------------------------------------------------------
    // Build Credential Entity
    // ---------------------------------------------------------------------
    private Credential buildCredentialEntity(
            CredentialEntityBuildParams params
    ) {
        return Credential.builder()
                .credentialId(params.credentialId())
                .userId(params.userId())
                .credentialType(params.credentialTypes())
                .credentialStatus(params.lifeCycleStatus().toString())
                .credentialFormat(params.credentialFormat().toString())
                .credentialData(params.credentialData())
                .jsonVc(params.vcJson().toString())
                .createdAt(params.currentTime())
                .updatedAt(params.currentTime())
                .build();
    }

    // ---------------------------------------------------------------------
    // Parsing JSON for Non-Signed Credential
    // ---------------------------------------------------------------------
    private Mono<JsonNode> parseAsPlainJson(String rawJson) {
        return Mono.fromCallable(() -> {
            if (rawJson == null || rawJson.isBlank()) {
                throw new ParseErrorException("Credential data is empty or null");
            }
            return objectMapper.readTree(rawJson);
        }).onErrorMap(e -> new ParseErrorException("Error parsing plain JSON credential: " + e.getMessage()));
    }

    // ---------------------------------------------------------------------
    // Extract Format
    // ---------------------------------------------------------------------
    private Mono<CredentialFormats> extractCredentialFormat(String format) {
        if (format == null || format.isBlank()) {
            return Mono.error(new IllegalArgumentException("CredentialResponse format is null"));
        }
        return switch (format) {
            case JWT_VC, JWT_VC_JSON -> Mono.just(CredentialFormats.JWT_VC);
            case CWT_VC -> Mono.just(CredentialFormats.CWT_VC);
            default -> Mono.error(new IllegalArgumentException(
                    "Unsupported credential format: " + format
            ));
        };
    }

    // ---------------------------------------------------------------------
    // Extract VC JSON based on Format
    // ---------------------------------------------------------------------
    private Mono<JsonNode> extractVcJson(CredentialResponse credentialResponse, String format) {
        return switch (format) {
            case JWT_VC, JWT_VC_JSON -> extractVcJsonFromJwt(credentialResponse.credentials().get(0).credential());
            case CWT_VC -> extractVcJsonFromCwt(credentialResponse.credentials().get(0).credential());
            default -> Mono.error(new IllegalArgumentException(
                    "Unsupported credential format"
            ));
        };
    }

    private Mono<JsonNode> extractVcJsonFromJwt(String jwtVc) {
        return Mono.fromCallable(() -> SignedJWT.parse(jwtVc))
                .flatMap(parsedJwt -> {
                    try {
                        JsonNode payload = objectMapper.readTree(parsedJwt.getPayload().toString());
                        JsonNode vcJson = payload.get("vc");
                        if (vcJson == null) {
                            return Mono.error(new ParseErrorException("VC JSON is missing in the payload"));
                        }
                        log.debug("Verifiable Credential JSON extracted from JWT: {}", vcJson);
                        return Mono.just(vcJson);
                    } catch (JsonProcessingException e) {
                        return Mono.error(new ParseErrorException("Error while processing JWT payload: " + e.getMessage()));
                    }
                });
    }

    private Mono<JsonNode> extractVcJsonFromCwt(String cwtVc) {
        return Mono.fromCallable(() -> {
            String vpJson = decodeToJSONstring(cwtVc);
            JsonNode vpNode = objectMapper.readTree(vpJson);
            JsonNode vcCbor = vpNode.at("/vp/verifiableCredential");
            if (vcCbor == null || !vcCbor.isTextual()) {
                throw new ParseErrorException("Verifiable Credential is missing in the CWT");
            }
            String vcJson = decodeToJSONstring(vcCbor.asText());
            return objectMapper.readTree(vcJson);
        }).onErrorMap(e -> new ParseErrorException("Error processing CWT: " + e.getMessage()));
    }

    // ---------------------------------------------------------------------
    // Extract ID and Types from the VC JSON
    // ---------------------------------------------------------------------
    private Mono<String> extractVerifiableCredentialIdFromVcJson(JsonNode vcJson) {
        return Mono.defer(() -> {
            if (vcJson == null) {
                return Mono.error(new IllegalArgumentException("vcJson is null"));
            }
            JsonNode idNode = vcJson.get("id");
            if (idNode != null && idNode.isTextual()) {
                log.debug("Verifiable Credential ID extracted: {}", idNode.asText());
                return Mono.just(idNode.asText());
            }
            return Mono.error(new IllegalArgumentException("Verifiable Credential ID is missing"));
        });
    }

    private Mono<List<String>> extractCredentialTypes(JsonNode vcJson) {
        return Mono.defer(() -> {
            if (vcJson == null) {
                return Mono.error(new IllegalArgumentException("vcJson is null"));
            }
            JsonNode typesNode = vcJson.get("type");
            if (typesNode != null && typesNode.isArray()) {
                List<String> types = new ArrayList<>();
                typesNode.forEach(typeNode -> types.add(typeNode.asText()));
                return Mono.just(types);
            }
            return Mono.error(new IllegalArgumentException("Credential types not found or not an array in vcJson"));
        });
    }

    // ---------------------------------------------------------------------
    // CWT Decoding (Base45 -> DEFLATE -> CBOR -> JSON)
    // ---------------------------------------------------------------------
    private String decodeToJSONstring(String encodedData) {
        try (
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                CompressorInputStream inputStream = new CompressorStreamFactory()
                        .createCompressorInputStream(
                                CompressorStreamFactory.DEFLATE,
                                new ByteArrayInputStream(Base45.getDecoder().decode(encodedData)))
        ) {
            IOUtils.copy(inputStream, out);
            CBORObject cbor = CBORObject.DecodeFromBytes(out.toByteArray());
            return cbor.ToJSONString();
        } catch (Exception e) {
            throw new ParseErrorException("Error decoding data: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------------
    // Update Credential (Deferred: ISSUED -> VALID, data, etc.)
    // ---------------------------------------------------------------------
    private Mono<Credential> updateCredentialEntity(Credential existingCredential, CredentialResponse credentialResponse) {
        existingCredential.setCredentialStatus(LifeCycleStatus.VALID.toString());
        existingCredential.setCredentialData(credentialResponse.credentials().get(0).credential());
        existingCredential.setUpdatedAt(Instant.now());
        return credentialRepository.save(existingCredential);
    }

    // ---------------------------------------------------------------------
    // parseJsonVc - If blank, returns empty object node
    // ---------------------------------------------------------------------
    private JsonNode parseJsonVc(String rawJson) {
        if (rawJson == null || rawJson.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(rawJson);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to parse credential JSON: " + e.getMessage(), e);
        }
    }
}