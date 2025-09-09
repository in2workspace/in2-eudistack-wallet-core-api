package es.in2.wallet.domain.exceptions;

public class RevokedCredentialErrorException extends RuntimeException {

    public RevokedCredentialErrorException(String message) {
        super(message);
    }
}