package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record CredentialRequest(
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @JsonProperty(value = "format", required = true) String format,
        @JsonProperty(value = "proof", required = true) Proof proof) {

    @Builder
    public record Proof(
            @JsonProperty(value = "proof_type", required = true) String proofType,
            @JsonProperty(value = "jwt", required = true) @NotBlank String jwt) {
    }
}
