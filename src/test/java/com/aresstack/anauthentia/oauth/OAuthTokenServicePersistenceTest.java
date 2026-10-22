package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuthTokenServicePersistenceTest {

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void preservesPreviousRefreshTokenWhenRotationCannotBePersisted() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET, Collections.singleton(REDIRECT_URI)));
        SwitchableRefreshTokenStore store = new SwitchableRefreshTokenStore();
        AuthorizationCodeService codes = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                clock,
                Duration.ofMinutes(5));
        OAuthTokenService service = new OAuthTokenService(
                codes,
                clients,
                store,
                new SecureRandom(),
                clock,
                Duration.ofSeconds(900),
                Duration.ofDays(30),
                true);

        String code = codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        TokenResponse initial = service.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);

        store.failWrites = true;
        assertThrows(RefreshTokenStoreException.class, () ->
                service.refreshAccessToken(CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken()));

        store.failWrites = false;
        TokenResponse retry = service.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken());

        assertNotEquals(initial.getRefreshToken(), retry.getRefreshToken());
        assertTrue(service.isBearerAuthorized("Bearer " + retry.getAccessToken()));
    }

    private static final class SwitchableRefreshTokenStore implements RefreshTokenStore {

        private final InMemoryRefreshTokenStore delegate = new InMemoryRefreshTokenStore();
        private boolean failWrites;

        @Override
        public Map<String, RefreshToken> load() {
            return delegate.load();
        }

        @Override
        public void save(Map<String, RefreshToken> tokens) {
            if (failWrites) {
                throw new RefreshTokenStoreException(
                        "Unable to persist refresh-token store", new IOException("Simulated disk failure"));
            }
            delegate.save(tokens);
        }
    }
}