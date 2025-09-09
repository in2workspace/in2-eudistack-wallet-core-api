package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

import java.util.List;
import java.util.Set;

@Schema(description = "This class is used to represent the Credential Offer by Reference using " +
        "credential_offer_uri parameter for a Pre-Authorized Code Flow. " +
        "For more information: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sending-credential-offer-by-")
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialOffer(
        @JsonProperty("credential_issuer")
        @NotBlank
        String credentialIssuer,
        @Schema(example = "[\"UniversityDegree\"]")
        @JsonProperty("credentials")
        List<Credential> credentials,

        @JsonProperty("credential_configuration_ids")
        Set<String> credentialConfigurationsIds,
        @Schema(implementation = Grant.class)
        @JsonProperty("grants")
        Grant grant
) {
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Credential(
            @JsonProperty("format")
            String format,

            @JsonProperty("types")
            List<String> types,

            @JsonProperty("trust_framework")
            TrustFramework trustFramework
    ) {
        @Builder
        @JsonIgnoreProperties(ignoreUnknown = true)
        public record TrustFramework(
                @JsonProperty("name")
                String name,

                @JsonProperty("type")
                String type,

                @JsonProperty("uri")
                String uri
        ) {
        }
    }
    @Builder
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Grant(
            @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code") PreAuthorizedCodeGrant preAuthorizedCodeGrant,
            @JsonProperty("authorization_code") AuthorizationCodeGrant authorizationCodeGrant
    ) {
        @Builder
        @JsonIgnoreProperties(ignoreUnknown = true)
        public record AuthorizationCodeGrant(@JsonProperty("issuer_state") String issuerState) {
        }

        @Builder
        @JsonIgnoreProperties(ignoreUnknown = true)
        public record PreAuthorizedCodeGrant(
                @JsonProperty("pre-authorized_code")
                String preAuthorizedCode,
                @JsonProperty("user_pin_required")
                boolean userPinRequired,

                @JsonProperty("tx_code")
                TxCode txCode

        ) {
            @Builder
            @JsonIgnoreProperties(ignoreUnknown = true)
            public record TxCode(
                    @JsonProperty("input_mode")
                    String inputMode,

                    @JsonProperty("length")
                    Integer length,

                    @JsonProperty("description")
                    String description

            ) {

            }
        }
    }
}
