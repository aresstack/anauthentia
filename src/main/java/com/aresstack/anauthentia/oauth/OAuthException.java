package com.aresstack.anauthentia.oauth;

/**
 * An OAuth protocol error that an HTTP adapter can map to an OAuth JSON response.
 */
public final class OAuthException extends RuntimeException {

    private final int statusCode;
    private final String error;
    private final String errorDescription;

    public OAuthException(int statusCode, String error) {
        this(statusCode, error, null);
    }

    public OAuthException(int statusCode, String error, String errorDescription) {
        super(errorDescription == null ? error : errorDescription);
        if (statusCode < 400 || statusCode > 599) {
            throw new IllegalArgumentException("statusCode must be an HTTP error status");
        }
        if (error == null || error.trim().isEmpty()) {
            throw new IllegalArgumentException("error must not be blank");
        }
        this.statusCode = statusCode;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}