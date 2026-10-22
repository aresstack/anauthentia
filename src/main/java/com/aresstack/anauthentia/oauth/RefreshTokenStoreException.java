package com.aresstack.anauthentia.oauth;

/**
 * Signals that refresh-token persistence failed.
 *
 * <p>Do not expose the underlying file contents or token values in protocol
 * responses or log messages. The cause is retained for internal diagnostics.
 */
public final class RefreshTokenStoreException extends RuntimeException {

    public RefreshTokenStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}