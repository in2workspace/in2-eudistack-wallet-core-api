package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum NotificationEvent {
    @JsonProperty("credential_accepted") CREDENTIAL_ACCEPTED,
    @JsonProperty("credential_failure") CREDENTIAL_FAILURE,
    @JsonProperty("credential_deleted") CREDENTIAL_DELETED
}

