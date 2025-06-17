package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record VcSelectorRequest(
        @JsonProperty("redirectUri") String redirectUri,
        @JsonProperty("state") String state,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("selectableVcList") List<VerifiableCredential> selectableVcList
) {

}
