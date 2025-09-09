package es.in2.wallet.domain.services.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.domain.services.ProofJWTService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class ProofJWTServiceImpl implements ProofJWTService {
    private final ObjectMapper objectMapper;
    @Override
    public Mono<JsonNode> buildCredentialRequest(String nonce, String issuer, String did) {
        try {
            log.info("Nonce: {}, Issuer: {}, DID: {}", nonce, issuer, did);
            Instant issueTime = Instant.now();
            Instant expirationTime = issueTime.plus(10, ChronoUnit.DAYS);
            JWTClaimsSet payload = new JWTClaimsSet.Builder()
                    .issuer(did)
                    .audience(issuer)
                    .issueTime(java.util.Date.from(issueTime))
                    .expirationTime(java.util.Date.from(expirationTime))
                    .claim("nonce", nonce)
                    .build();
            log.info("Payload: {}", payload);
            return Mono.just(objectMapper.readTree(payload.toString()));
        }
        catch (JsonProcessingException e){
            log.error("Error while parsing the JWT payload", e);
            return Mono.error(new ParseErrorException("Error while parsing the JWT payload: " + e.getMessage()));
        }
    }
}
