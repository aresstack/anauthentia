package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuthTokenServiceTest {

    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String OTHER_CLIENT_ID = "other-client";
    private static final String OTHER_CLIENT_SECRET = "other-secret";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void issuesAndValidatesAccessTokenAfterAuthorizationCodeExchange() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        TokenResponse response = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        assertEquals("Bearer", response.getTokenType());
        assertEquals("mcp", response.getScope());
        assertEquals(900, response.getExpiresIn());
        assertEquals(BearerAuthResult.OK,
                fixture.tokens.checkBearerAuth("Bearer " + response.getAccessToken()));
    }

    @Test
    void rejectsInvalidClientCredentials() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);

        OAuthException exception = assertThrows(OAuthException.class, () ->
                fixture.tokens.exchangeAuthorizationCode(
                        CLIENT_ID, "wrong-secret", fixture.issueCode(), REDIRECT_URI, VERIFIER));

        assertEquals(401, exception.getStatusCode());
        assertEquals("invalid_client", exception.getError());
    }

    @Test
    void returnsSameResponseForIdenticalAuthorizationReplayWithinWindow() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        String code = fixture.issueCode();

        TokenResponse first = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);
        TokenResponse replay = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);

        assertEquals(first.getAccessToken(), replay.getAccessToken());
        assertEquals(first.getRefreshToken(), replay.getRefreshToken());
    }

    @Test
    void rotatesRefreshTokenAndReturnsSameResponseForShortReplayWindow() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        TokenResponse initial = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        TokenResponse refreshed = fixture.tokens.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken());
        TokenResponse replay = fixture.tokens.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken());

        assertTrue(!initial.getRefreshToken().equals(refreshed.getRefreshToken()));
        assertEquals(refreshed.getAccessToken(), replay.getAccessToken());
        assertEquals(refreshed.getRefreshToken(), replay.getRefreshToken());
        assertEquals(BearerAuthResult.OK,
                fixture.tokens.checkBearerAuth("Bearer " + refreshed.getAccessToken()));
    }

    @Test
    void rejectsRefreshTokenUsedByAnotherClientWithoutRevokingIt() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        TokenResponse initial = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        OAuthException exception = assertThrows(OAuthException.class, () ->
                fixture.tokens.refreshAccessToken(
                        OTHER_CLIENT_ID, OTHER_CLIENT_SECRET, initial.getRefreshToken()));

        assertEquals("invalid_grant", exception.getError());
        TokenResponse ownerRefresh = fixture.tokens.refreshAccessToken(
                CLIENT_ID, CLIENT_SECRET, initial.getRefreshToken());
        assertTrue(!initial.getRefreshToken().equals(ownerRefresh.getRefreshToken()));
    }

    @Test
    void expiresAccessTokens() {
        AtomicReference<Instant> now = new AtomicReference<Instant>(NOW);
        Fixture fixture = createFixture(new MutableClock(now), false);
        TokenResponse initial = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        now.set(NOW.plusSeconds(901));

        assertEquals(BearerAuthResult.EXPIRED_TOKEN,
                fixture.tokens.checkBearerAuth("Bearer " + initial.getAccessToken()));
    }

    @Test
    void rejectsInvalidPkceExchange() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);

        OAuthException exception = assertThrows(OAuthException.class, () ->
                fixture.tokens.exchangeAuthorizationCode(
                        CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER + "x"));

        assertEquals("invalid_grant", exception.getError());
    }

    private static Fixture createFixture(Clock clock, boolean rotateRefreshTokens) {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(
                CLIENT_ID, CLIENT_SECRET, Collections.singleton(REDIRECT_URI)));
        clients.register(new OAuthClient(
                OTHER_CLIENT_ID, OTHER_CLIENT_SECRET, Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService authorizationCodes = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                clock,
                Duration.ofMinutes(5));
        OAuthTokenService tokens = new OAuthTokenService(
                authorizationCodes,
                clients,
                new InMemoryRefreshTokenStore(),
                new SecureRandom(),
                clock,
                Duration.ofSeconds(900),
                Duration.ofDays(30),
                rotateRefreshTokens);
        return new Fixture(authorizationCodes, tokens);
    }

    private static final class Fixture {
        private final AuthorizationCodeService authorizationCodes;
        private final OAuthTokenService tokens;

        private Fixture(AuthorizationCodeService authorizationCodes, OAuthTokenService tokens) {
            this.authorizationCodes = authorizationCodes;
            this.tokens = tokens;
        }

        private String issueCode() {
            return authorizationCodes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        }
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> instant;

        private MutableClock(AtomicReference<Instant> instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}