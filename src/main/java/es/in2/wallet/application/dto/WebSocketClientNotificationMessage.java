package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record WebSocketClientNotificationMessage(
        @JsonProperty("id")
        String id,
        @JsonProperty("decision")
        String decision
) {
}

