package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record WebSocketClientMessage(
        @JsonProperty("id")
        String id,
        @JsonProperty("pin")
        String pin
) {
}

