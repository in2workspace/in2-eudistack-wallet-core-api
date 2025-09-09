package es.in2.wallet.domain.services;

import es.in2.wallet.application.dto.VcSelectorResponse;
import es.in2.wallet.application.dto.VerifiableCredential;
import reactor.core.publisher.Mono;

public interface PresentationService {
    Mono<String> createSignedVerifiablePresentation(String processId, String authorizationToken, VcSelectorResponse vcSelectorResponse,String nonce, String audience);
    Mono<String> createSignedTurnstileVerifiablePresentation(String processId, String authorizationToken, VerifiableCredential verifiableCredential, String nonce, String audience);
}
