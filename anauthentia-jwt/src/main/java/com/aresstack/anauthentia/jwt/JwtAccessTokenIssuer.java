package com.aresstack.anauthentia.jwt;

import com.aresstack.anauthentia.oauth.GrantAwareAccessTokenGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

/**
 * Issue RFC 9068 access tokens: RS256-signed JWTs with {@code typ=at+jwt},
 * issuer, per-service audience, subject (client), scope, expiry, and kid.
 *
 * <p>Plugs into {@code OAuthTokenService} as its access-token generator so the
 * standard code/refresh flows hand out verifiable JWTs.
 */
public final class JwtAccessTokenIssuer implements GrantAwareAccessTokenGenerator {

    static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    private final String issuer;
    private final String audience;
    private final JwtKeyRing keyRing;

    public JwtAccessTokenIssuer(String issuer, String audience, JwtKeyRing keyRing) {
        this.issuer = requireNonBlank(issuer, "issuer");
        this.audience = requireNonBlank(audience, "audience");
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
    }

    /** Issue a token for the configured default issuer/audience. */
    public String generate(String clientId, String scope, Instant issuedAt, Instant expiresAt) {
        return generate(clientId, scope, null, issuedAt, expiresAt);
    }

    /**
     * {@inheritDoc}
     *
     * <p>A non-blank RFC 8707 {@code resource} binds the token to exactly that
     * resource: {@code aud} becomes the resource and {@code iss} its origin
     * (resource without the trailing slash) — the per-site issuer model where
     * every protected site discovers, authorizes and validates under its own
     * public host while sharing one key ring.
     */
    @Override
    public String generate(String clientId, String scope, String resource,
                           Instant issuedAt, Instant expiresAt) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");

        boolean bound = resource != null && !resource.trim().isEmpty();
        String tokenAudience = bound ? resource.trim() : audience;
        String tokenIssuer = bound ? stripTrailingSlash(resource.trim()) : issuer;
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(tokenIssuer)
                .audience(tokenAudience)
                .subject(clientId)
                .claim("client_id", clientId)
                .claim("scope", scope)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(ACCESS_TOKEN_TYPE)
                .keyID(keyRing.currentKeyId())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(keyRing.currentKey()));
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to sign the access token", exception);
        }
        return jwt.serialize();
    }

    private static String stripTrailingSlash(String value) {
        String result = value;
        while (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
