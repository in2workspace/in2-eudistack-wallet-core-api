package es.in2.wallet.api.exception;

import es.in2.wallet.application.dto.ApiErrorResponse;
import es.in2.wallet.domain.exceptions.*;
import es.in2.wallet.infrastructure.core.controller.GlobalExceptionHandlerController;
import es.in2.wallet.application.dto.GlobalErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.function.BiFunction;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerControllerTest {
    private static GlobalExceptionHandlerController globalExceptionHandlerController;
    private ServerHttpRequest request;
    private RequestPath requestPath;

    static Stream<Arguments> provideData() {
        List<Class<?>> classes = new ArrayList<>(Arrays.asList(
                FailedCommunicationException.class,
                FailedDeserializingException.class,
                FailedSerializingException.class,
                JwtInvalidFormatException.class,
                NoSuchQrContentException.class,
                ParseErrorException.class,
                NoSuchVerifiableCredentialException.class,
                NoSuchDeferredCredentialMetadataException.class,
                InvalidPinException.class,
                CredentialNotAvailableException.class,
                IssuerNotAuthorizedException.class,
                AttestationUnauthorizedException.class,
                RevokedCredentialErrorException.class,
                AttestationClientErrorException.class,
                AttestationServerErrorException.class,
                TimeoutException.class

        ));

        List<String> messages = new ArrayList<>(Arrays.asList(
                "FailedCommunication",
                "FailedDeserializing",
                "FailedSerializing",
                "JwtInvalidFormat",
                "NoSuchQrContent",
                "ParseError",
                "NoSuchVerifiableCredential",
                "NoSuchTransaction",
                "InvalidPin",
                "CredentialNotAvailable",
                "IssuerNotAuthorizedException",
                "Attestation Unauthorized Response",
                "Attestation Forbidden Response",
                "Attestation Client Error",
                "Attestation Server Error",
                "Timeout Error"
        ));

        List<BiFunction<Exception, ServerHttpRequest, Mono<GlobalErrorMessage>>> methods = new ArrayList<>(Arrays.asList(
                (ex, req) -> globalExceptionHandlerController.failedCommunicationException((FailedCommunicationException) ex, req),
                (ex, req) -> globalExceptionHandlerController.failedDeserializingException((FailedDeserializingException) ex, req),
                (ex, req) -> globalExceptionHandlerController.failedSerializingException((FailedSerializingException) ex, req),
                (ex, req) -> globalExceptionHandlerController.jwtInvalidFormatException((JwtInvalidFormatException) ex, req),
                (ex, req) -> globalExceptionHandlerController.noSuchQrContentException((NoSuchQrContentException) ex, req),
                (ex, req) -> globalExceptionHandlerController.parseErrorException((ParseErrorException) ex, req),
                (ex, req) -> globalExceptionHandlerController.noSuchVerifiableCredentialException((NoSuchVerifiableCredentialException) ex, req),
                (ex, req) -> globalExceptionHandlerController.noSuchTransactionException((NoSuchDeferredCredentialMetadataException) ex, req),
                (ex, req) -> globalExceptionHandlerController.invalidPinException((InvalidPinException) ex, req),
                (ex, req) -> globalExceptionHandlerController.credentialNotAvailableException((CredentialNotAvailableException) ex, req),
                (ex, req) -> globalExceptionHandlerController.issuerNotAuthorizedException((IssuerNotAuthorizedException) ex, req),
                (ex, req) -> globalExceptionHandlerController.attestationUnauthorizedException((AttestationUnauthorizedException) ex, req),
                (ex, req) -> globalExceptionHandlerController.revokedCredentialErrorException((RevokedCredentialErrorException) ex, req),
                (ex, req) -> globalExceptionHandlerController.attestationClientErrorException((AttestationClientErrorException) ex, req),
                (ex, req) -> globalExceptionHandlerController.attestationServerErrorException((AttestationServerErrorException) ex, req),
                (ex, req) -> globalExceptionHandlerController.timeoutErrorException((TimeoutException) ex, req)

        ));

        Map<Class<? extends Exception>, String> exceptionMethodNames = new HashMap<>();
        exceptionMethodNames.put(FailedCommunicationException.class, "FailedCommunicationException");
        exceptionMethodNames.put(FailedDeserializingException.class, "FailedDeserializingException");
        exceptionMethodNames.put(FailedSerializingException.class, "FailedSerializingException");
        exceptionMethodNames.put(JwtInvalidFormatException.class, "JwtInvalidFormatException");
        exceptionMethodNames.put(NoSuchQrContentException.class, "NoSuchQrContentException");
        exceptionMethodNames.put(ParseErrorException.class, "ParseErrorException");
        exceptionMethodNames.put(NoSuchVerifiableCredentialException.class, "NoSuchVerifiableCredentialException");
        exceptionMethodNames.put(NoSuchDeferredCredentialMetadataException.class, "NoSuchTransactionException");
        exceptionMethodNames.put(InvalidPinException.class, "InvalidPinException");
        exceptionMethodNames.put(CredentialNotAvailableException.class, "CredentialNotAvailableException");
        exceptionMethodNames.put(IssuerNotAuthorizedException.class, "IssuerNotAuthorizedException");
        exceptionMethodNames.put(AttestationUnauthorizedException.class, "Attestation Unauthorized Response");
        exceptionMethodNames.put(RevokedCredentialErrorException.class, "Attestation Forbidden Response");
        exceptionMethodNames.put(AttestationClientErrorException.class, "Attestation Client Error");
        exceptionMethodNames.put(AttestationServerErrorException.class, "Attestation Server Error");
        exceptionMethodNames.put(TimeoutException.class, "Timeout Error");

        return IntStream.range(0, classes.size())
                .mapToObj(i -> Arguments.of(classes.get(i), messages.get(i), methods.get(i % methods.size()), exceptionMethodNames));

    }

    @BeforeEach
    void setup() {
        request = mock(ServerHttpRequest.class);
        requestPath = mock(RequestPath.class);
        globalExceptionHandlerController = new GlobalExceptionHandlerController();
    }

    @ParameterizedTest
    @MethodSource("provideData")
    void testExceptions(Class<? extends Exception> exceptionClass, String message,
                        BiFunction<Exception, ServerHttpRequest, Mono<GlobalErrorMessage>> method,
                        Map<Class<? extends Exception>, String> exceptionMethodNames) throws NoSuchMethodException,
            InvocationTargetException, InstantiationException, IllegalAccessException {
        // Mock
        when(request.getPath()).thenReturn(requestPath);
        // Act
        Exception exception = exceptionClass.getConstructor(String.class)
                .newInstance(message);

        String title = exceptionMethodNames.get(exceptionClass);

        GlobalErrorMessage globalErrorMessage =
                GlobalErrorMessage.builder()
                        .title(title)
                        .message(message)
                        .path(String.valueOf(requestPath))
                        .build();
        //Assert
        StepVerifier.create(method.apply(exception, request))
                .expectNext(globalErrorMessage)
                .verifyComplete();
    }

    @Test
    void handleIllegalArgumentExceptionTest() {
        String message = "Invalid input provided";
        String path = "/api/example";

        IllegalArgumentException exception = new IllegalArgumentException(message);

        when(request.getPath()).thenReturn(requestPath);
        when(requestPath.toString()).thenReturn(path);

        ApiErrorResponse expectedResponse = ApiErrorResponse.builder()
                .type("https://wallet.in2.es/errors/invalid-request")
                .title("Invalid Request")
                .status(HttpStatus.BAD_REQUEST.value())
                .detail(message)
                .instance(path)
                .build();

        StepVerifier.create(globalExceptionHandlerController.handleIllegalArgumentException(exception, request))
                .expectNext(expectedResponse)
                .verifyComplete();
    }

}
