package es.in2.wallet.api.facade;

import es.in2.wallet.application.dto.VerifiableCredential;
import es.in2.wallet.application.workflows.presentation.impl.AttestationExchangeTurnstileWorkflowImpl;
import es.in2.wallet.domain.exceptions.ParseErrorException;
import es.in2.wallet.application.dto.CredentialsBasicInfo;
import es.in2.wallet.domain.services.CborGenerationService;
import es.in2.wallet.domain.services.PresentationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AttestationExchangeTurnstileWorkflowImplTest {
    @Mock
    private PresentationService presentationService;
    @Mock
    private CborGenerationService cborGenerationService;
    @InjectMocks
    private AttestationExchangeTurnstileWorkflowImpl credentialPresentationForTurnstileServiceFacade;
    @Test
    void createVerifiablePresentationForTurnstileTestSuccess() {
        String processId = "123";
        String authorizationToken = "authToken";
        String audience = "vpTurnstile";
        String expectedVp = "vp";
        String expectedCBOR = "vp_cbor";
        VerifiableCredential credential = VerifiableCredential.builder().id("id").build();
        when(presentationService.createSignedTurnstileVerifiablePresentation(processId, authorizationToken, credential, credential.id(), audience)).thenReturn(Mono.just("vp"));
        when(cborGenerationService.generateCbor(processId, expectedVp)).thenReturn(Mono.just("vp_cbor"));

        StepVerifier.create(credentialPresentationForTurnstileServiceFacade.createVerifiablePresentationForTurnstile(processId, authorizationToken, credential))
                .expectNext(expectedCBOR)
                .verifyComplete();

    }
    @Test
    void createVerifiablePresentationForTurnstileTestFailure() {
        String processId = "123";
        String authorizationToken = "authToken";
        String audience = "vpTurnstile";
        String expectedVp = "vp";
        VerifiableCredential credential = VerifiableCredential.builder().id("id").build();
        when(presentationService.createSignedTurnstileVerifiablePresentation(processId, authorizationToken, credential, credential.id(), audience)).thenReturn(Mono.just("vp"));
        when(cborGenerationService.generateCbor(processId, expectedVp)).thenThrow(new ParseErrorException("Failed to parse token payload"));

        StepVerifier.create(credentialPresentationForTurnstileServiceFacade.createVerifiablePresentationForTurnstile(processId, authorizationToken, credential))
                .expectErrorMatches(error -> error instanceof ParseErrorException && error.getMessage().contains("Failed to parse token payload"))
                .verify();

    }
}
