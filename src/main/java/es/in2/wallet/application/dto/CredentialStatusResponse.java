package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialStatusResponse(
        @JsonProperty("nonce") String credentialNonce) {
}
