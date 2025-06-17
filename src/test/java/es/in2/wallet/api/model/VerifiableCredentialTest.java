package es.in2.wallet.api.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.wallet.application.dto.VerifiableCredential;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class VerifiableCredentialTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testSerialization() throws JsonProcessingException {
        JsonNode issuerNode = objectMapper.createObjectNode().put("id", "did:example:issuer");
        JsonNode credentialSubjectNode = objectMapper.createObjectNode().put("id", "did:example:subject");

        VerifiableCredential verifiableCredential = VerifiableCredential.builder()
                .type(List.of("VerifiableCredential", "ExampleCredential"))
                .context(List.of("https://www.w3.org/2018/credentials/v1"))
                .id("urn:uuid:1234")
                .issuer(issuerNode)
                .validFrom("2020-01-01T00:00:00Z")
                .credentialSubject(credentialSubjectNode)
                .build();

        String json = objectMapper.writeValueAsString(verifiableCredential);
        assertThat(json).contains("VerifiableCredential", "https://www.w3.org/2018/credentials/v1", "urn:uuid:1234");
    }

    @Test
    void testDeserialization() throws JsonProcessingException {
        String json = """
                {
                    "type": ["VerifiableCredential", "ExampleCredential"],
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "id": "urn:uuid:1234",
                    "issuer": {"id": "did:example:issuer"},
                    "issuanceDate": "2020-01-01T00:00:00Z",
                    "issued": "2020-01-01T00:00:00Z",
                    "validFrom": "2020-01-01T00:00:00Z",
                    "expirationDate": "2021-01-01T00:00:00Z",
                    "credentialSubject": {"id": "did:example:subject"}
                }
                """;

        VerifiableCredential verifiableCredential = objectMapper.readValue(json, VerifiableCredential.class);

        assertThat(verifiableCredential.id()).isEqualTo("urn:uuid:1234");
        assertThat(verifiableCredential.type()).contains("VerifiableCredential", "ExampleCredential");
        assertThat(verifiableCredential.issuer().get("id").asText()).isEqualTo("did:example:issuer");
        assertThat(verifiableCredential.credentialSubject().get("id").asText()).isEqualTo("did:example:subject");
    }
}
