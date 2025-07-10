package es.in2.wallet.domain.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Builder
@EqualsAndHashCode(of = "id")
@Table("wallet.deferred_credential_metadata")
public class DeferredCredentialMetadata {
    @Id
    @Column("id")
    private UUID id;

    @Column("transaction_id")
    private UUID transactionId;

    @Column("credential_id")
    private String credentialId;

    @Column("access_token")
    private String accessToken;

    @Column("deferred_endpoint")
    private String deferredEndpoint;

    @Column("created_at")
    private Instant createdAt;

    @Column("updated_at")
    private Instant updatedAt;
}
