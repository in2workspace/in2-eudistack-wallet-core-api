package es.in2.wallet.infrastructure.core.controller;

import es.in2.wallet.application.dto.ApiErrorResponse;
import es.in2.wallet.domain.exceptions.*;
import es.in2.wallet.application.dto.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeoutException;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandlerController {
    @ExceptionHandler(FailedCommunicationException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    @ResponseBody
    public Mono<GlobalErrorMessage> failedCommunicationException(FailedCommunicationException failedCommunicationException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        log.debug("failedCommunicationException", failedCommunicationException);
        return Mono.just(GlobalErrorMessage.builder()
                .title("FailedCommunicationException")
                .message(failedCommunicationException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(FailedDeserializingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public Mono<GlobalErrorMessage> failedDeserializingException(FailedDeserializingException failedDeserializingException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("FailedDeserializingException")
                .message(failedDeserializingException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(FailedSerializingException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public Mono<GlobalErrorMessage> failedSerializingException(FailedSerializingException failedSerializingException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("FailedSerializingException")
                .message(failedSerializingException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(JwtInvalidFormatException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Mono<GlobalErrorMessage> jwtInvalidFormatException(JwtInvalidFormatException jwtInvalidFormatException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("JwtInvalidFormatException")
                .message(jwtInvalidFormatException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(NoSuchQrContentException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Mono<GlobalErrorMessage> noSuchQrContentException(NoSuchQrContentException noSuchQrContentException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("NoSuchQrContentException")
                .message(noSuchQrContentException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(ParseErrorException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Mono<GlobalErrorMessage> parseErrorException(ParseErrorException parseErrorException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("ParseErrorException")
                .message(parseErrorException.getMessage())
                .path(path)
                .build());
    }
    @ExceptionHandler(NoSuchVerifiableCredentialException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Mono<GlobalErrorMessage> noSuchVerifiableCredentialException(NoSuchVerifiableCredentialException noSuchVerifiableCredentialException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("NoSuchVerifiableCredentialException")
                .message(noSuchVerifiableCredentialException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(NoSuchDeferredCredentialMetadataException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Mono<GlobalErrorMessage> noSuchTransactionException(NoSuchDeferredCredentialMetadataException noSuchDeferredCredentialMetadataException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("NoSuchTransactionException")
                .message(noSuchDeferredCredentialMetadataException.getMessage())
                .path(path)
                .build());
    }
    @ExceptionHandler(InvalidPinException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ResponseBody
    public Mono<GlobalErrorMessage> invalidPinException(InvalidPinException invalidPinException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("InvalidPinException")
                .message(invalidPinException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(CredentialNotAvailableException.class)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @ResponseBody
    public Mono<GlobalErrorMessage> credentialNotAvailableException(CredentialNotAvailableException credentialNotAvailableException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("CredentialNotAvailableException")
                .message(credentialNotAvailableException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(IssuerNotAuthorizedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ResponseBody
    public Mono<GlobalErrorMessage> issuerNotAuthorizedException(IssuerNotAuthorizedException issuerNotAuthorizedException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("IssuerNotAuthorizedException")
                .message(issuerNotAuthorizedException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(AttestationUnauthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ResponseBody
    public Mono<GlobalErrorMessage> attestationUnauthorizedException(AttestationUnauthorizedException attestationUnauthorizedException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("Attestation Unauthorized Response")
                .message(attestationUnauthorizedException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(RevokedCredentialErrorException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ResponseBody
    public Mono<GlobalErrorMessage> revokedCredentialErrorException(RevokedCredentialErrorException revokedCredentialErrorException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("Attestation Forbidden Response")
                .message(revokedCredentialErrorException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(AttestationClientErrorException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Mono<GlobalErrorMessage> attestationClientErrorException(AttestationClientErrorException attestationClientErrorException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("Attestation Client Error")
                .message(attestationClientErrorException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(AttestationServerErrorException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ResponseBody
    public Mono<GlobalErrorMessage> attestationServerErrorException(AttestationServerErrorException attestationServerErrorException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("Attestation Server Error")
                .message(attestationServerErrorException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(TimeoutException.class)
    @ResponseStatus(HttpStatus.REQUEST_TIMEOUT)
    @ResponseBody
    public Mono<GlobalErrorMessage> timeoutErrorException(TimeoutException timeoutException, ServerHttpRequest request) {
        String path = String.valueOf(request.getPath());
        return Mono.just(GlobalErrorMessage.builder()
                .title("Timeout Error")
                .message(timeoutException.getMessage())
                .path(path)
                .build());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ResponseBody
    public Mono<ApiErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex, ServerHttpRequest request) {
        String path = request.getPath().toString();
        return Mono.just(ApiErrorResponse.builder()
                .type("https://wallet.in2.es/errors/invalid-request")
                .title("Invalid Request")
                .status(HttpStatus.BAD_REQUEST.value())
                .detail(ex.getMessage())
                .instance(path)
                .build());
    }
}
