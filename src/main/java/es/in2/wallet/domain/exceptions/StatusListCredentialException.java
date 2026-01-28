package es.in2.wallet.domain.exceptions;

public class StatusListCredentialException extends RuntimeException {
    public StatusListCredentialException(String message) {
        super(message);
    }

    public StatusListCredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}