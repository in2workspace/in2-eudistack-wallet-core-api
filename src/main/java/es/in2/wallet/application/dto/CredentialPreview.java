package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

@Builder
public record CredentialPreview(
        @JsonProperty("power") JsonNode power,
        @JsonProperty("subjectName") String subjectName,
        @JsonProperty("organization") String organization,
        @JsonProperty("expirationDate") String expirationDate
) {
}



