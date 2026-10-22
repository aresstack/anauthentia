package com.aresstack.anauthentia.oauth;

/**
 * Generate access-token values using a host-specific policy.
 *
 * <p>Use the default OAuthTokenService constructor to generate cryptographically
 * random opaque values. Custom implementations are intended for controlled
 * compatibility scenarios, such as a fixed token configured by a host.
 */
public interface AccessTokenGenerator {

    String generate();
}