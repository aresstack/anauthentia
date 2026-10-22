package com.aresstack.anauthentia.jwt;

import com.aresstack.anauthentia.oauth.AuthorizationCodeService;
import com.aresstack.anauthentia.oauth.InMemoryAuthorizationCodeStore;
import com.aresstack.anauthentia.oauth.InMemoryOAuthClientRegistry;
import com.aresstack.anauthentia.oauth.InMemoryRefreshTokenStore;
import com.aresstack.anauthentia.oauth.OAuthClient;
import com.aresstack.anauthentia.oauth.OAuthException;
import com.aresstack.anauthentia.oauth.OAuthTokenService;
import com.aresstack.anauthentia.oauth.TokenResponse;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Audience-Isolation (RFC 8707): one central key ring and client, but every
 * grant is bound to its target resource. A token or grant for AskAI must be
 * worthless at Pyloros and vice versa.
 */
class ResourceIsolationTest {

    private static final String CLIENT_ID = "chatgpt";
    private static final String CLIENT_SECRET = "secret";
    private static final String REDIRECT_URI = "https://chatgpt.com/cb";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static final String ASKAI = "https://askai.example.org/";
    private static final String PYLOROS = "https://pyloros.example.org/";

    private final JwtKeyRing keyRing = JwtKeyRing.generate("central-key");
    private final InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
    private final AuthorizationCodeService codes;
    private final OAuthTokenService service;

    ResourceIsolationTest() {
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET,
                Collections.singleton(REDIRECT_URI)));
        Clock clock = Clock.systemUTC();
        codes = new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clients,
                new SecureRandom(), clock, Duration.ofMinutes(5));
        service = new OAuthTokenService(codes, clients, new InMemoryRefreshTokenStore(),
                new SecureRandom(), clock, Duration.ofMinutes(10), Duration.ofDays(30), true,
                // Default-Issuer/-Audience sind nur Fallback; die Ressource gewinnt.
                new JwtAccessTokenIssuer("https://fallback.example.org",
                        "https://fallback.example.org/", keyRing));
    }

    private String authorizeFor(String resource) {
        String redirect = codes.authorize("code", CLIENT_ID, REDIRECT_URI, null, "mcp",
                CHALLENGE, "S256", resource);
        int index = redirect.indexOf("code=");
        int end = redirect.indexOf('&', index);
        return redirect.substring(index + 5, end < 0 ? redirect.length() : end);
    }

    private JwtAccessTokenValidator validatorFor(String resource) {
        String issuer = resource.substring(0, resource.length() - 1);
        return new JwtAccessTokenValidator(issuer, resource, keyRing.publicJwkSet());
    }

    @Test
    void tokenForAskaiIsRejectedByPylorosAndViceVersa() {
        TokenResponse askai = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "authorization_code", authorizeFor(ASKAI), null, REDIRECT_URI, VERIFIER, ASKAI);
        TokenResponse pyloros = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "authorization_code", authorizeFor(PYLOROS), null, REDIRECT_URI, VERIFIER, PYLOROS);

        assertTrue(validatorFor(ASKAI).validate(askai.getAccessToken()).isPresent());
        assertTrue(validatorFor(PYLOROS).validate(pyloros.getAccessToken()).isPresent());

        // Die eigentliche Isolation: Kreuz-Validierung scheitert.
        assertFalse(validatorFor(PYLOROS).validate(askai.getAccessToken()).isPresent(),
                "an AskAI token must be rejected by Pyloros");
        assertFalse(validatorFor(ASKAI).validate(pyloros.getAccessToken()).isPresent(),
                "a Pyloros token must be rejected by AskAI");
    }

    @Test
    void authorizationCodeBoundToOneResourceCannotBeExchangedAtAnother() {
        String codeForAskai = authorizeFor(ASKAI);
        OAuthException rejected = assertThrows(OAuthException.class, () ->
                service.exchangeToken(CLIENT_ID, CLIENT_SECRET, "authorization_code",
                        codeForAskai, null, REDIRECT_URI, VERIFIER, PYLOROS));
        assertEquals("invalid_grant", rejected.getError());
    }

    @Test
    void refreshTokenBoundToOneResourceCannotRefreshAtAnother() {
        TokenResponse askai = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "authorization_code", authorizeFor(ASKAI), null, REDIRECT_URI, VERIFIER, ASKAI);

        OAuthException rejected = assertThrows(OAuthException.class, () ->
                service.exchangeToken(CLIENT_ID, CLIENT_SECRET, "refresh_token",
                        null, askai.getRefreshToken(), null, null, PYLOROS));
        assertEquals("invalid_grant", rejected.getError());

        // Am richtigen Host refresht derselbe Token — und bleibt gebunden.
        TokenResponse refreshed = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "refresh_token", null, askai.getRefreshToken(), null, null, ASKAI);
        assertTrue(validatorFor(ASKAI).validate(refreshed.getAccessToken()).isPresent());
        assertFalse(validatorFor(PYLOROS).validate(refreshed.getAccessToken()).isPresent());
    }
}
