ALTER TABLE identity_wallet.deferred_credential_metadata
    DROP CONSTRAINT fk_credential;

ALTER TABLE identity_wallet.credential
    ALTER COLUMN credential_id TYPE TEXT;

ALTER TABLE identity_wallet.deferred_credential_metadata
    ALTER COLUMN credential_id TYPE TEXT;

ALTER TABLE identity_wallet.deferred_credential_metadata
    ADD CONSTRAINT fk_credential FOREIGN KEY (credential_id) REFERENCES identity_wallet.credential (credential_id) ON DELETE CASCADE;
