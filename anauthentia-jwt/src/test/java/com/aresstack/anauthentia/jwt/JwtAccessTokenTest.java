package com.aresstack.anauthentia.jwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtAccessTokenTest {

    private static final String ISSUER = "https://askai.example.com";
    private static final String AUDIENCE = "https://askai.example.com/";

    private final JwtKeyRing keyRing = JwtKeyRing.generate("key-1");
    private final JwtAccessTokenIssuer issuer = new JwtAccessTokenIssuer(ISSUER, AUDIENCE, keyRing);
    private final JwtAccessTokenValidator validator =
            new JwtAccessTokenValidator(ISSUER, AUDIENCE, keyRing.publicJwkSet());

    private String issueValid() {
        Instant now = Instant.now();
        return issuer.generate("chatgpt-client", "mcp", now, now.plus(Duration.ofMinutes(10)));
    }

    @Test
    void roundTripCarriesClientScopeAndExpiry() {
        Optional<JwtAccessToken> result = validator.validate(issueValid());
        assertTrue(result.isPresent());
        assertEquals("chatgpt-client", result.get().getClientId());
        assertTrue(result.get().hasScope("mcp"));
        assertTrue(result.get().getExpiresAt().isAfter(Instant.now()));
    }

    @Test
    void rejectsTamperedSignature() {
        String token = issueValid();
        String tampered = token.substring(0, token.length() - 4)
                + (token.endsWith("AAAA") ? "BBBB" : "AAAA");
        assertFalse(validator.validate(tampered).isPresent());
    }

    @Test
    void rejectsUnsignedAlgNoneToken() throws Exception {
        Instant now = Instant.now();
        PlainJWT unsigned = new PlainJWT(new JWTClaimsSet.Builder()
                .issuer(ISSUER).audience(AUDIENCE).subject("chatgpt-client")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600))).build());
        assertFalse(validator.validate(unsigned.serialize()).isPresent());
    }

    @Test
    void rejectsHs256TokenEvenWithMatchingClaims() throws Exception {
        Instant now = Instant.now();
        byte[] key = new byte[32];
        SignedJWT hmac = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(new JOSEObjectType("at+jwt")).keyID("key-1").build(),
                new JWTClaimsSet.Builder()
                        .issuer(ISSUER).audience(AUDIENCE).subject("chatgpt-client")
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(600))).build());
        hmac.sign(new MACSigner(key));
        assertFalse(validator.validate(hmac.serialize()).isPresent());
    }

    @Test
    void rejectsWrongAudienceAndWrongIssuer() {
        String token = issueValid();
        assertFalse(new JwtAccessTokenValidator(ISSUER, "https://pyloros.example.com/",
                keyRing.publicJwkSet()).validate(token).isPresent());
        assertFalse(new JwtAccessTokenValidator("https://evil.example.com", AUDIENCE,
                keyRing.publicJwkSet()).validate(token).isPresent());
    }

    @Test
    void rejectsTokenExpiredBeyondClockSkew() {
        Instant past = Instant.now().minus(Duration.ofMinutes(30));
        String expired = issuer.generate("chatgpt-client", "mcp",
                past, past.plus(Duration.ofMinutes(10)));
        assertFalse(validator.validate(expired).isPresent());
    }

    @Test
    void rejectsWrongTypHeader() throws Exception {
        Instant now = Instant.now();
        SignedJWT plainTyp = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(JOSEObjectType.JWT).keyID(keyRing.currentKeyId()).build(),
                new JWTClaimsSet.Builder()
                        .issuer(ISSUER).audience(AUDIENCE).subject("chatgpt-client")
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(600))).build());
        plainTyp.sign(new RSASSASigner(keyRing.currentKey()));
        assertFalse(validator.validate(plainTyp.serialize()).isPresent());
    }

    @Test
    void rejectsUnknownKid() {
        JwtKeyRing foreign = JwtKeyRing.generate("foreign-key");
        String token = new JwtAccessTokenIssuer(ISSUER, AUDIENCE, foreign)
                .generate("chatgpt-client", "mcp", Instant.now(),
                        Instant.now().plus(Duration.ofMinutes(10)));
        assertFalse(validator.validate(token).isPresent());
    }

    @Test
    void rotationKeepsOldTokensValidAndSignsWithNewKey() {
        String oldToken = issueValid();
        JwtKeyRing rotated = keyRing.rotate("key-2");
        JwtAccessTokenValidator rotatedValidator =
                new JwtAccessTokenValidator(ISSUER, AUDIENCE, rotated.publicJwkSet());

        assertTrue(rotatedValidator.validate(oldToken).isPresent(),
                "tokens signed before rotation must stay valid until expiry");

        String newToken = new JwtAccessTokenIssuer(ISSUER, AUDIENCE, rotated)
                .generate("chatgpt-client", "mcp", Instant.now(),
                        Instant.now().plus(Duration.ofMinutes(10)));
        assertTrue(rotatedValidator.validate(newToken).isPresent());
        assertEquals("key-2", rotated.currentKeyId());
    }

    @Test
    void publicJwksExposesNoPrivateKeyMaterial() {
        String jwks = keyRing.rotate("key-2").publicJwksJson();
        assertTrue(jwks.contains("\"kid\":\"key-2\"") || jwks.contains("\"kid\" : \"key-2\""));
        assertFalse(jwks.contains("\"d\""), "JWKS must not contain the private exponent");
        assertFalse(jwks.contains("\"p\""), "JWKS must not contain prime factors");
    }

    @Test
    void garbageAndEmptyTokensAreRejected() {
        assertFalse(validator.validate(null).isPresent());
        assertFalse(validator.validate("").isPresent());
        assertFalse(validator.validate("not.a.jwt").isPresent());
    }
}
