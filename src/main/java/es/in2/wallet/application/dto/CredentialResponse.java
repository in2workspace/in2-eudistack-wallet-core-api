package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.util.List;

@Schema(description = "Implements the credential response according to " +
        "https://github.com/hesusruiz/EUDIMVP/blob/main/issuance.md#credential-response")
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialResponse(

        @JsonProperty("credentials") List<Credentials> credentials,
        @JsonProperty("transaction_id") String transactionId
) {
        @Builder
        public record Credentials(
                @JsonProperty("credential") String credential

        ) {
        }
}



