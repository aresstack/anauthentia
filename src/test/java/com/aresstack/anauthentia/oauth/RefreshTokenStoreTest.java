package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class RefreshTokenStoreTest {

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void restoresRefreshTokensFromHostProvidedStore() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET, Collections.singleton(REDIRECT_URI)));
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();

        AuthorizationCodeService firstCodeService = createCodeService(clients, clock);
        OAuthTokenService firstService = createTokenService(firstCodeService, clients, store, clock);
        String code = firstCodeService.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        TokenResponse initial = firstService.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);

        AuthorizationCodeService restartedCodeService = createCodeService(clients, clock);
        OAuthTokenService restartedService = createTokenService(restartedCodeService, clients, store, clock);
        TokenResponse refreshed = restartedService.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken());

        assertNotNull(refreshed.getAccessToken());
        assertNotEquals(initial.getRefreshToken(), refreshed.getRefreshToken());
    }

    private static AuthorizationCodeService createCodeService(
            OAuthClientRegistry clients, Clock clock) {
        return new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                clock,
                Duration.ofMinutes(5));
    }

    private static OAuthTokenService createTokenService(
            AuthorizationCodeService codes,
            OAuthClientRegistry clients,
            RefreshTokenStore store,
            Clock clock) {
        return new OAuthTokenService(
                codes,
                clients,
                store,
                new SecureRandom(),
                clock,
                Duration.ofSeconds(900),
                Duration.ofDays(30),
                true);
    }
}