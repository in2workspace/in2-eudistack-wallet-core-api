package es.in2.wallet.domain.entities;

import java.util.Arrays;
import java.util.Objects;

public record StatusListCredentialData(
        String issuer,
        String statusPurpose,
        byte[] rawBitstringBytes
) {
    public StatusListCredentialData {
        Objects.requireNonNull(statusPurpose, "statusPurpose cannot be null");
        Objects.requireNonNull(rawBitstringBytes, "rawBitstringBytes cannot be null");
        rawBitstringBytes = rawBitstringBytes.clone();
    }

    @Override
    public byte[] rawBitstringBytes() {
        return rawBitstringBytes.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof StatusListCredentialData other)) return false;
        return Objects.equals(issuer, other.issuer)
                && Objects.equals(statusPurpose, other.statusPurpose)
                && Arrays.equals(rawBitstringBytes, other.rawBitstringBytes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(issuer, statusPurpose);
        result = 31 * result + Arrays.hashCode(rawBitstringBytes);
        return result;
    }

    @Override
    public String toString() {
        return "StatusListCredentialData[" +
                "issuer=" + issuer +
                ", statusPurpose=" + statusPurpose +
                ", rawBitstringBytesLength=" + rawBitstringBytes.length +
                ']';
    }
}