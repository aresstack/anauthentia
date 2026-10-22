package com.aresstack.anauthentia.oauth;

import java.time.Instant;

/**
 * Generate access-token values that embed grant context, such as signed JWTs
 * carrying client, scope, and expiry claims (RFC 9068).
 *
 * <p>The returned value must conform to Bearer token syntax, be unique, and be
 * unguessable or unforgeable. The service still tracks expiry itself; the
 * supplied instants let the generator embed matching {@code iat}/{@code exp}
 * claims so offline validators agree with the issuer.
 */
public interface GrantAwareAccessTokenGenerator {

    /**
     * Generate a new access-token value for the supplied grant.
     *
     * @param clientId the authenticated OAuth client
     * @param scope the space-separated granted scopes
     * @param resource the RFC 8707 target resource the grant is bound to, or {@code null}
     * @param issuedAt the issuance instant
     * @param expiresAt the expiry instant the service will enforce
     */
    String generate(String clientId, String scope, String resource,
                    Instant issuedAt, Instant expiresAt);
}
