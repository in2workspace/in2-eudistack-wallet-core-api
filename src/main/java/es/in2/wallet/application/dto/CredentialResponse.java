package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialResponse(
        @JsonProperty(value = "credentials") List<Credential> credentials,
        @JsonProperty("transaction_id") String transactionId,
        @JsonProperty("interval") Long interval,
        @JsonProperty("notification_id") String notificationId) {

    @Builder
    public record Credential(@JsonProperty String credential) {

    }
}
