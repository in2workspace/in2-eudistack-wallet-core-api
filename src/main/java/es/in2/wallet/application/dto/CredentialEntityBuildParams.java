package es.in2.wallet.application.dto;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.wallet.domain.enums.CredentialFormats;
import es.in2.wallet.domain.enums.CredentialStatus;
import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Builder
public record CredentialEntityBuildParams(
        String credentialId,
        UUID userId,
        List<String> credentialTypes,
        CredentialFormats credentialFormat,
        String credentialData,
        JsonNode vcJson,
        CredentialStatus credentialStatus,
        Instant currentTime
) {}

