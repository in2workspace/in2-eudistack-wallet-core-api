package es.in2.wallet.application.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record CredentialPower(
        @JsonProperty("function") String function,
        @JsonProperty("action") List<String> action
) {}