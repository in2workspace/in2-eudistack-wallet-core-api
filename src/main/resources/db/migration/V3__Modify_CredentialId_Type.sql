ALTER TABLE wallet.deferred_credential_metadata
    DROP CONSTRAINT fk_credential;

ALTER TABLE wallet.credential
    ALTER COLUMN credential_id TYPE TEXT;

ALTER TABLE wallet.deferred_credential_metadata
    ALTER COLUMN credential_id TYPE TEXT;

ALTER TABLE wallet.deferred_credential_metadata
    ADD CONSTRAINT fk_credential FOREIGN KEY (credential_id) REFERENCES wallet.credential (credential_id) ON DELETE CASCADE;
