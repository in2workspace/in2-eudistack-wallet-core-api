package es.in2.wallet.application.dto;

import lombok.Builder;

@Builder
public record TokenInfo(String accessToken, String refreshToken, long tokenObtainedAt, long expiresIn) {
}
