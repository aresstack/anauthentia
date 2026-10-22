package com.aresstack.anauthentia.oauth;

/**
 * Generate unique, unguessable access-token values that conform to Bearer token syntax.
 *
 * <p>Use the default OAuthTokenService constructor for cryptographically random opaque values.
 * Never return a constant value or reuse a previously issued token.
 */
public interface AccessTokenGenerator {

    /** Generate a new unique access-token value. */
    String generate();
}