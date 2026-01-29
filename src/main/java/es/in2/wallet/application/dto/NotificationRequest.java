package es.in2.wallet.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record NotificationRequest(
        @NotBlank String notificationId,
        @NotNull NotificationEvent event,
        String eventDescription
) {}