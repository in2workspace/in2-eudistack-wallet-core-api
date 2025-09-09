package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record VcSelectorResponse(
        @JsonProperty("redirectUri") String redirectUri,
        @JsonProperty("state") String state,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("selectedVcList") List<VerifiableCredential> selectedVcList

) {
}
