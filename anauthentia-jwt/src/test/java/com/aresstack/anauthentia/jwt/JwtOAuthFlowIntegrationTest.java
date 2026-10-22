package com.aresstack.anauthentia.jwt;

import com.aresstack.anauthentia.oauth.AuthorizationCodeService;
import com.aresstack.anauthentia.oauth.InMemoryAuthorizationCodeStore;
import com.aresstack.anauthentia.oauth.InMemoryOAuthClientRegistry;
import com.aresstack.anauthentia.oauth.InMemoryRefreshTokenStore;
import com.aresstack.anauthentia.oauth.OAuthClient;
import com.aresstack.anauthentia.oauth.OAuthTokenService;
import com.aresstack.anauthentia.oauth.TokenResponse;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end: the standard authorization-code flow of OAuthTokenService hands
 * out RS256 JWTs that a resource server validates offline via JWKS.
 */
class JwtOAuthFlowIntegrationTest {

    private static final String CLIENT_ID = "chatgpt-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String ISSUER = "https://askai.example.com";
    private static final String AUDIENCE = "https://askai.example.com/";

    @Test
    void authorizationCodeFlowIssuesOfflineVerifiableJwt() {
        Clock clock = Clock.systemUTC();
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET,
                Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService codes = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(), clients, new SecureRandom(),
                clock, Duration.ofMinutes(5));

        JwtKeyRing keyRing = JwtKeyRing.generate("key-1");
        OAuthTokenService service = new OAuthTokenService(
                codes, clients, new InMemoryRefreshTokenStore(), new SecureRandom(), clock,
                Duration.ofMinutes(10), Duration.ofDays(30), true,
                new JwtAccessTokenIssuer(ISSUER, AUDIENCE, keyRing));

        String code = codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        TokenResponse response = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "authorization_code", code, null, REDIRECT_URI, VERIFIER);

        // Der Authorization Server selbst akzeptiert den Token weiterhin.
        assertTrue(service.isBearerAuthorized("Bearer " + response.getAccessToken()));

        // Der Resource Server validiert offline, nur mit dem öffentlichen JWKS.
        JwtAccessTokenValidator validator =
                new JwtAccessTokenValidator(ISSUER, AUDIENCE, keyRing.publicJwkSet());
        Optional<JwtAccessToken> validated = validator.validate(response.getAccessToken());
        assertTrue(validated.isPresent());
        assertEquals(CLIENT_ID, validated.get().getClientId());
        assertTrue(validated.get().hasScope("mcp"));

        // Refresh liefert ebenfalls ein gültiges JWT.
        TokenResponse refreshed = service.exchangeToken(CLIENT_ID, CLIENT_SECRET,
                "refresh_token", null, response.getRefreshToken(), null, null);
        assertTrue(validator.validate(refreshed.getAccessToken()).isPresent());
    }
}
