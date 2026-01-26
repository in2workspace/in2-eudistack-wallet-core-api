package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record WebSocketServerNotificationMessage(
        @JsonProperty("decision") Boolean decision,
        @JsonProperty("credentialPreview") CredentialPreview credentialPreview,
        @JsonProperty("timeout") long timeout
) {
}



