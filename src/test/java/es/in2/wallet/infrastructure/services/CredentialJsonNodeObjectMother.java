package es.in2.wallet.infrastructure.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class CredentialJsonNodeObjectMother {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CredentialJsonNodeObjectMother() {
        // prevent instantiation
    }

    public static JsonNode credentialLearEmployeeMandateDid() {
        return read("""
            {
              "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/extra"],
              "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "issuer": {
                "id": "did:example:issuer"
              },
              "validUntil": "2026-12-31T23:59:59Z",
              "validFrom": "2023-01-01T00:00:00Z",
              "credentialSubject": {
                "name": "Credential Name",
                "description": "Credential Description",
                "mandate": {
                  "mandatee": {
                    "id": "did:example:987"
                  }
                }
              }
            }
            """);
    }

    public static JsonNode credentialLearEmployeeSubjectDid() {
        return read("""
            {
              "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.com/context/extra"],
              "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
              "type": ["VerifiableCredential", "LEARCredentialEmployee"],
              "issuer": {
                "id": "did:example:issuer"
              },
              "validUntil": "2026-12-31T23:59:59Z",
              "validFrom": "2023-01-01T00:00:00Z",
              "credentialSubject": {
                "name": "Credential Name",
                "description": "Credential Description",
                "id": "did:example:987"
              }
            }
            """);
    }

    public static JsonNode basicCredentialSubjectDid() {
        return read("""
                {
                    "id": "8c7a6213-544d-450d-8e3d-b41fa9009198",
                    "type": [
                        "VerifiableCredential",
                        "AnotherType"
                    ],
                    "credentialSubject" : {
                        "id" : "did:example:basic"
                    },
                    "validUntil": "2026-12-31T23:59:59Z"
                }
                """);
    }

    private static JsonNode read(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid test JSON", e);
        }
    }
}
