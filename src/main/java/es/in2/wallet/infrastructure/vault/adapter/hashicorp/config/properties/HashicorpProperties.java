package es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("security.vault.hashicorp")
public record HashicorpProperties(
        @NotNull String host,
        @NotNull String port,
        @NotNull String scheme,
        @NotNull String token) {
}
