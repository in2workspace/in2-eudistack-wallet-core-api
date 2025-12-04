package es.in2.wallet.infrastructure.vault.adapter.hashicorp.config;

import es.in2.wallet.infrastructure.appconfiguration.service.GenericConfigAdapter;
import es.in2.wallet.infrastructure.appconfiguration.util.ConfigAdapterFactory;
import es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.properties.HashicorpProperties;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.Base64;

@Component
public class HashicorpConfig {
    private final GenericConfigAdapter genericConfigAdapter;
    private final HashicorpProperties hashicorpProperties;

    public HashicorpConfig(ConfigAdapterFactory configAdapterFactory, HashicorpProperties hashicorpProperties) {
        this.genericConfigAdapter = configAdapterFactory.getAdapter();
        this.hashicorpProperties = hashicorpProperties;
    }

    public String getSecretPath() {
        String secretsPath = Path.of(hashicorpProperties.secretsMount()).toString();
        return genericConfigAdapter.getConfiguration(secretsPath);
    }

    public String getVaultUrl() {
        return genericConfigAdapter.getConfiguration(hashicorpProperties.url());
    }

    public String getVaultToken() {
        String rawToken = hashicorpProperties.token();
        return decodeIfBase64(rawToken);
    }

    private String decodeIfBase64(String token) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(token);
            return new String(decodedBytes).trim();
        } catch (IllegalArgumentException ex) {
            return token.trim();
        }
    }
}
