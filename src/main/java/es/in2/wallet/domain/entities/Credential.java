package es.in2.wallet.domain.entities;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
@Builder
@EqualsAndHashCode(of = "id")
@Table("wallet.credential")
public class Credential {
    @Id
    @Column("id")
    private UUID id;

    @Column("credential_id")
    private String credentialId;

    @Column("user_id")
    private UUID userId;

    @Column("credential_type")
    private List<String> credentialType;

    @Column("credential_status")
    private String credentialStatus;

    @Column("credential_format")
    private String credentialFormat;

    @Column("credential_data")
    private String credentialData;

    @Column("json_vc")
    private String jsonVc;

    @Column("created_at")
    private Instant createdAt;

    @Column("updated_at")
    private Instant updatedAt;
}