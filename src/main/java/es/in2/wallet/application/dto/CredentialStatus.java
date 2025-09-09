package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialStatus(
        @JsonProperty("id") String id,
        @JsonProperty("type") String type,
        @JsonProperty("statusPurpose") String statusPurpose,
        @JsonProperty("statusListIndex") String statusListIndex,
        @JsonProperty("statusListCredential") String statusListCredential
) {
}
