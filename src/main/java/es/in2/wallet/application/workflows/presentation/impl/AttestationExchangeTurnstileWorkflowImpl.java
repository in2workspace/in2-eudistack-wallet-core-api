package es.in2.wallet.application.workflows.presentation.impl;

import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.workflows.presentation.AttestationExchangeTurnstileWorkflow;
import es.in2.wallet.domain.services.CborGenerationService;
import es.in2.wallet.domain.services.PresentationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


@Slf4j
@Service
@RequiredArgsConstructor
public class AttestationExchangeTurnstileWorkflowImpl implements AttestationExchangeTurnstileWorkflow {
    private final PresentationService presentationService;
    private final CborGenerationService cborGenerationService;

    @Override
    public Mono<String> createVerifiablePresentationForTurnstile(String processId, String authorizationToken, VerifiableCredential credential) {
        return generateAudience()
                .flatMap(audience -> presentationService.createSignedTurnstileVerifiablePresentation(processId, authorizationToken, credential, credential.id(), audience)
                )
                .flatMap(vp -> cborGenerationService.generateCbor(processId, vp));
    }

    private static Mono<String> generateAudience() {
        return Mono.just("vpTurnstile");
    }
}
