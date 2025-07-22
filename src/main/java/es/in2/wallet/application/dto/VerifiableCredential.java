package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record VerifiableCredential(
        @JsonProperty("@context")
        List<String> context,
        @JsonProperty("id")
        String id,
        @JsonProperty("type")
        List<String> type,
        @JsonProperty("lifeCycleStatus")
        String lifeCycleStatus,
        @JsonProperty("name")
        String name,
        @JsonProperty("description")
        String description,
        @JsonProperty("issuer") JsonNode issuer,
        @JsonProperty("validFrom") String validFrom,
        @JsonProperty("validUntil") String validUntil, // New Credential version attribute
        @JsonProperty("credentialSubject") JsonNode credentialSubject,
        @JsonProperty("credentialStatus") JsonNode credentialStatus,
        @JsonProperty("credentialEncoded") String credentialEncoded

) {
}
