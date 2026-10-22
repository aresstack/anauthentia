package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** RFC 7009: revocation requires client auth, never discloses token existence. */
class RefreshTokenRevocationTest {

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
    private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    private final AuthorizationCodeService codes;
    private final OAuthTokenService service;

    RefreshTokenRevocationTest() {
        clients.register(new OAuthClient(CLIENT_ID, CLIENT_SECRET,
                Collections.singleton(REDIRECT_URI)));
        codes = new AuthorizationCodeService(new InMemoryAuthorizationCodeStore(), clients,
                new SecureRandom(), clock, Duration.ofMinutes(5));
        service = new OAuthTokenService(codes, clients, store, new SecureRandom(), clock,
                Duration.ofSeconds(900), Duration.ofDays(30), true);
    }

    @Test
    void revokedRefreshTokenIsRejectedAndRemovedFromTheStore() {
        TokenResponse issued = exchange();
        service.revokeRefreshToken(CLIENT_ID, CLIENT_SECRET, issued.getRefreshToken());

        assertThrows(OAuthException.class, () ->
                service.refreshAccessToken(CLIENT_ID, CLIENT_SECRET, issued.getRefreshToken()));
        assertTrue(store.load().isEmpty(), "revocation must reach the persistent store");
    }

    @Test
    void revokingUnknownTokenSucceedsSilently() {
        assertDoesNotThrow(() ->
                service.revokeRefreshToken(CLIENT_ID, CLIENT_SECRET, "unknown-token"));
        assertDoesNotThrow(() -> service.revokeRefreshToken(CLIENT_ID, CLIENT_SECRET, null));
    }

    @Test
    void revocationRequiresClientAuthentication() {
        TokenResponse issued = exchange();
        assertThrows(OAuthException.class, () ->
                service.revokeRefreshToken(CLIENT_ID, "wrong-secret", issued.getRefreshToken()));
        // Der Token bleibt gültig.
        assertDoesNotThrow(() ->
                service.refreshAccessToken(CLIENT_ID, CLIENT_SECRET, issued.getRefreshToken()));
    }

    @Test
    void foreignClientCannotRevokeAnotherClientsToken() {
        clients.register(new OAuthClient("other-client", "other-secret",
                Collections.singleton(REDIRECT_URI)));
        TokenResponse issued = exchange();

        service.revokeRefreshToken("other-client", "other-secret", issued.getRefreshToken());

        assertDoesNotThrow(() ->
                service.refreshAccessToken(CLIENT_ID, CLIENT_SECRET, issued.getRefreshToken()));
    }

    private TokenResponse exchange() {
        String code = codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        return service.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);
    }
}
