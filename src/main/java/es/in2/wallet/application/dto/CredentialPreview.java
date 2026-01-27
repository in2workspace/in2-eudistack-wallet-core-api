package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialPreview(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("subjectName") String subjectName,
        @JsonProperty("organization") String organization,
        @JsonProperty("expirationDate") String expirationDate
) {
}



