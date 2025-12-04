package es.in2.wallet.vault.adapter.hashicorp.config;

import es.in2.wallet.infrastructure.appconfiguration.service.GenericConfigAdapter;
import es.in2.wallet.infrastructure.appconfiguration.util.ConfigAdapterFactory;
import es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.HashicorpConfig;
import es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.properties.HashicorpProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class HashicorpConfigTest {

    private ConfigAdapterFactory configAdapterFactory;
    private GenericConfigAdapter genericConfigAdapter;
    private HashicorpProperties hashicorpProperties;
    private HashicorpConfig hashicorpConfig;

    @BeforeEach
    void setUp() {
        configAdapterFactory = mock(ConfigAdapterFactory.class);
        genericConfigAdapter = mock(GenericConfigAdapter.class);
        hashicorpProperties = mock(HashicorpProperties.class);

        when(configAdapterFactory.getAdapter()).thenReturn(genericConfigAdapter);

        hashicorpConfig = new HashicorpConfig(configAdapterFactory, hashicorpProperties);
    }

    @Test
    void getSecretPath_shouldReturnValueFromGenericAdapter() {
        // given
        when(hashicorpProperties.secretsMount()).thenReturn("secret/mount");
        when(genericConfigAdapter.getConfiguration("/secret/mount"))
                .thenReturn("secret/path");

        // when
        String result = hashicorpConfig.getSecretPath();

        // then
        assertEquals("secret/path", result);
    }

    @Test
    void getVaultUrl_shouldReturnValueFromGenericAdapter() {
        when(hashicorpProperties.url()).thenReturn("vault.url.key");
        when(genericConfigAdapter.getConfiguration("vault.url.key")).thenReturn("https://vault.example.com");

        String result = hashicorpConfig.getVaultUrl();

        assertEquals("https://vault.example.com", result);
    }

    @Test
    void getVaultToken_shouldDecodeBase64Token() {
        String rawToken = Base64.getEncoder().encodeToString("my-secret-token".getBytes());
        when(hashicorpProperties.token()).thenReturn(rawToken);

        String result = hashicorpConfig.getVaultToken();

        assertEquals("my-secret-token", result);
    }

    @Test
    void getVaultToken_shouldReturnPlainTokenIfNotBase64() {
        String rawToken = "plain-token";
        when(hashicorpProperties.token()).thenReturn(rawToken);

        String result = hashicorpConfig.getVaultToken();

        assertEquals("plain-token", result);
    }
}
