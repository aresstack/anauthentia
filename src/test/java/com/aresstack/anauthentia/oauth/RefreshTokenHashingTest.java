package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Refresh tokens must never reach the store in plaintext: a leaked store file
 * must not yield usable credentials. Legacy plaintext stores migrate on load.
 */
class RefreshTokenHashingTest {

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void storePersistsOnlyDigestsNeverThePlaintextRefreshToken() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        InMemoryOAuthClientRegistry clients = registry();
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        AuthorizationCodeService codes = codeService(clients, clock);
        OAuthTokenService service = tokenService(codes, clients, store, clock, true);

        String code = codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        TokenResponse response = service.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);

        Map<String, RefreshToken> persisted = store.load();
        assertEquals(1, persisted.size());
        for (String key : persisted.keySet()) {
            assertTrue(key.startsWith("s256:"), "store keys must be digests");
            assertFalse(key.contains(response.getRefreshToken()),
                    "plaintext refresh token must not appear in the store");
        }

        // Der Klartext-Token aus der Antwort funktioniert weiterhin.
        TokenResponse refreshed = service.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, response.getRefreshToken());
        assertTrue(service.isBearerAuthorized("Bearer " + refreshed.getAccessToken()));
    }

    @Test
    void legacyPlaintextStoreEntriesMigrateAndKeepWorking() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        InMemoryOAuthClientRegistry clients = registry();
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        String legacyPlaintextToken = "legacy-plaintext-refresh-token-value";
        store.save(Collections.singletonMap(legacyPlaintextToken,
                new RefreshToken(CLIENT_ID, "mcp", NOW.plus(Duration.ofDays(10)))));

        OAuthTokenService service = tokenService(
                codeService(clients, clock), clients, store, clock, true);

        TokenResponse refreshed = service.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, legacyPlaintextToken);
        assertTrue(service.isBearerAuthorized("Bearer " + refreshed.getAccessToken()));

        // Nach der Rotation enthält der Store nur noch Digests.
        for (String key : store.load().keySet()) {
            assertTrue(key.startsWith("s256:"));
        }
    }

    private static InMemoryOAuthClientRegistry registry() {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET,
                Collections.singleton(REDIRECT_URI)));
        return clients;
    }

    private static AuthorizationCodeService codeService(
            InMemoryOAuthClientRegistry clients, Clock clock) {
        return new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clients,
                new SecureRandom(), clock, Duration.ofMinutes(5));
    }

    private static OAuthTokenService tokenService(
            AuthorizationCodeService codes, InMemoryOAuthClientRegistry clients,
            RefreshTokenStore store, Clock clock, boolean rotation) {
        return new OAuthTokenService(codes, clients, store, new SecureRandom(), clock,
                Duration.ofSeconds(900), Duration.ofDays(30), rotation);
    }
}
