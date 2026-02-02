package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialPreview(
        @JsonProperty("powers") String powers,
        @JsonProperty("subjectName") String subjectName,
        @JsonProperty("organization") String organization,
        @JsonProperty("expirationDate") String expirationDate
) {
}



