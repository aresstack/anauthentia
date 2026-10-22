package com.aresstack.anauthentia.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;

/**
 * Strict offline validation of RFC 9068 access tokens for a resource server.
 *
 * <p>Nothing is trusted implicitly: only RS256 against the supplied JWKS, only
 * {@code typ=at+jwt}, exact issuer, the resource's own audience, and expiry
 * within a bounded clock skew. Every rejection yields an empty result without
 * disclosing which check failed.
 */
public final class JwtAccessTokenValidator {

    private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

    private final DefaultJWTProcessor<SecurityContext> processor;

    public JwtAccessTokenValidator(String expectedIssuer, String expectedAudience, JWKSet publicKeys) {
        this(expectedIssuer, expectedAudience, publicKeys, DEFAULT_CLOCK_SKEW);
    }

    public JwtAccessTokenValidator(
            String expectedIssuer, String expectedAudience, JWKSet publicKeys, Duration clockSkew) {
        requireNonBlank(expectedIssuer, "expectedIssuer");
        requireNonBlank(expectedAudience, "expectedAudience");
        Objects.requireNonNull(publicKeys, "publicKeys");
        Objects.requireNonNull(clockSkew, "clockSkew");
        if (clockSkew.isNegative() || clockSkew.getSeconds() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("clockSkew must be a non-negative number of seconds");
        }

        processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<SecurityContext>(
                JwtAccessTokenIssuer.ACCESS_TOKEN_TYPE));
        // Algorithmus-Allowlist: ausschließlich RS256; "none"/HS* scheitern hier.
        processor.setJWSKeySelector(new JWSVerificationKeySelector<SecurityContext>(
                JWSAlgorithm.RS256, new ImmutableJWKSet<SecurityContext>(toPublicOnly(publicKeys))));
        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
                new DefaultJWTClaimsVerifier<SecurityContext>(
                        expectedAudience,
                        new JWTClaimsSet.Builder().issuer(expectedIssuer).build(),
                        new HashSet<String>(Arrays.asList("exp", "iat", "sub")));
        claimsVerifier.setMaxClockSkew((int) clockSkew.getSeconds());
        processor.setJWTClaimsSetVerifier(claimsVerifier);
    }

    /**
     * Validate a compact JWT. Empty for every malformed, foreign, downgraded,
     * expired, or otherwise non-conforming token.
     */
    public Optional<JwtAccessToken> validate(String token) {
        if (token == null || token.trim().isEmpty()) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(token, null);
            String clientId = claims.getSubject();
            if (clientId == null || clientId.trim().isEmpty()) {
                return Optional.empty();
            }
            Object scope = claims.getClaim("scope");
            return Optional.of(new JwtAccessToken(
                    clientId,
                    scope == null ? "" : String.valueOf(scope),
                    claims.getExpirationTime().toInstant(),
                    claims.getJWTID()));
        } catch (Exception rejected) {
            // Signatur, Typ, Algorithmus, Issuer, Audience, Ablauf oder Parsing —
            // der Grund wird bewusst nicht offengelegt.
            return Optional.empty();
        }
    }

    private static JWKSet toPublicOnly(JWKSet keys) {
        // Schutz vor Fehlbedienung: selbst wenn ein Host versehentlich private
        // Schlüssel übergibt, validiert dieser Validator nur gegen den
        // öffentlichen Teil und hält keine privaten Schlüssel.
        return keys.toPublicJWKSet();
    }

    private static void requireNonBlank(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
