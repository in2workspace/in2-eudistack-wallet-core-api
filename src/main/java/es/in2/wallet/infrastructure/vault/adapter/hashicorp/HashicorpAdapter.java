package es.in2.wallet.infrastructure.vault.adapter.hashicorp;

import es.in2.wallet.infrastructure.vault.adapter.hashicorp.model.HashicorpSecretRequest;
import es.in2.wallet.infrastructure.vault.adapter.hashicorp.config.HashicorpConfig;
import es.in2.wallet.infrastructure.vault.adapter.hashicorp.model.HashicorpSecretResponse;
import es.in2.wallet.infrastructure.vault.model.KeyVaultSecret;
import es.in2.wallet.infrastructure.vault.service.GenericVaultService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.ReactiveVaultOperations;
import org.springframework.vault.core.SecretNotFoundException;
import reactor.core.publisher.Mono;

import java.util.Objects;


@Service
@Slf4j
public class HashicorpAdapter implements GenericVaultService {
    public static final String DATA = "/data/";

    private final ReactiveVaultOperations vaultOperations;
    private final String hashicorpSecretPath;

    public HashicorpAdapter(ReactiveVaultOperations vaultOperations, HashicorpConfig hashicorpConfig) {
        this.vaultOperations = vaultOperations;
        this.hashicorpSecretPath = hashicorpConfig.getSecretPath();
    }

    @Override
    public Mono<Void> saveSecret(String key, KeyVaultSecret secret) {
        HashicorpSecretRequest hashicorpSecret = new HashicorpSecretRequest(key, secret.value());

        // data is needed to write data in hashicorp api v2
        // Further information: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
        return vaultOperations.write(hashicorpSecretPath + DATA + key, hashicorpSecret)
                .doOnSuccess(voidValue -> log.debug("Secret saved successfully"))
                .doOnError(error -> log.error("Error saving secret: {}", error.getMessage(), error))
                .onErrorResume(Exception.class, Mono::error)
                .then();
    }

    @Override
    public Mono<KeyVaultSecret> getSecret(String key) {
        return vaultOperations.read(hashicorpSecretPath + DATA + key)
                .flatMap(response -> {
                    HashicorpSecretResponse hashicorpSecretResponse;

                    try {
                        hashicorpSecretResponse = new HashicorpSecretResponse(Objects.requireNonNull(response.getData()));
                    } catch (Exception e) {
                        return Mono.error(new RuntimeException("Vault response could not be parsed"));
                    }

                    if (hashicorpSecretResponse.data() == null || hashicorpSecretResponse.data().isEmpty() || hashicorpSecretResponse.data().get(key) == null) {
                        return Mono.error(new SecretNotFoundException("Secret not found: " + key, key));
                    }

                    KeyVaultSecret keyVaultSecret = new KeyVaultSecret(hashicorpSecretResponse.data().get(key));
                    return Mono.just(keyVaultSecret);
                })
                .doOnSuccess(secret -> log.debug("Secret retrieved successfully"))
                .doOnError(error -> log.error("Error retrieving secret: " + key, error.getMessage(), error))
                .onErrorResume(Exception.class, Mono::error);
    }

    @Override
    public Mono<Void> deleteSecret(String key) {
        return vaultOperations.delete(hashicorpSecretPath + DATA + key)
                .doOnSuccess(voidValue -> log.debug("Secret deleted successfully"))
                .onErrorResume(Exception.class, e -> {
                    log.error("Error deleting secret: " + key, e.getMessage(), e);
                    return Mono.error(e);
                });
    }

}
