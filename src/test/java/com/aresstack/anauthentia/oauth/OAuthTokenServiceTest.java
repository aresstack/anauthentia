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

    @Test
    void usesHostProvidedAccessTokenGenerator() {
        Fixture fixture = createFixture(
                Clock.fixed(NOW, ZoneOffset.UTC), true, () -> "fixed-access-token");

        TokenResponse response = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        assertEquals("fixed-access-token", response.getAccessToken());
        assertEquals(BearerAuthResult.OK,
                fixture.tokens.checkBearerAuth("Bearer fixed-access-token"));
    }

    @Test
    void resolvesClientIdentityAndGrantedScopeForValidBearerToken() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        String code = fixture.authorizationCodes.issue(CLIENT_ID, REDIRECT_URI, "mcp read", CHALLENGE);
        TokenResponse response = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI, VERIFIER);

        java.util.Optional<BearerTokenPrincipal> principal =
                fixture.tokens.resolveBearerToken("Bearer " + response.getAccessToken());

        assertTrue(principal.isPresent());
        assertEquals(CLIENT_ID, principal.get().getClientId());
        assertEquals("mcp read", principal.get().getScope());
        assertEquals(NOW.plusSeconds(900), principal.get().getExpiresAt());
        assertTrue(principal.get().includesScope("mcp"));
        assertTrue(principal.get().includesScope("read"));
        assertTrue(!principal.get().includesScope("admin"));
        assertTrue(!principal.get().includesScope("mcp read"));
    }

    @Test
    void doesNotResolveUnknownOrExpiredBearerTokens() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);

        assertTrue(!fixture.tokens.resolveBearerToken("Bearer unknown-token").isPresent());
        assertTrue(!fixture.tokens.resolveBearerToken("Basic unknown-token").isPresent());
    }
    @Test
    void supportsPublicClientsWithoutClientSecretsWhenPkceIsUsed() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService codes = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(), clients, new SecureRandom(), clock, Duration.ofMinutes(5));
        OAuthTokenService tokens = new OAuthTokenService(
                codes, clients, new InMemoryRefreshTokenStore(), new SecureRandom(), clock,
                Duration.ofSeconds(900), Duration.ofDays(30), true);

        String code = codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        TokenResponse response = tokens.exchangeAuthorizationCode(
                CLIENT_ID, null, code, REDIRECT_URI, VERIFIER);

        assertEquals(BearerAuthResult.OK, tokens.checkBearerAuth("Bearer " + response.getAccessToken()));
        assertThrows(OAuthException.class, () ->
                tokens.exchangeAuthorizationCode(CLIENT_ID, "unexpected-secret",
                        codes.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE), REDIRECT_URI, VERIFIER));
    }

    @Test
    void rejectsMalformedAccessTokenGeneratorOutput() {
        Fixture fixture = createFixture(
                Clock.fixed(NOW, ZoneOffset.UTC), true, () -> "invalid token value");

        assertThrows(IllegalStateException.class, () ->
                fixture.tokens.exchangeAuthorizationCode(
                        CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER));
    }
    private static Fixture createFixture(Clock clock, boolean rotateRefreshTokens) {
        return createFixture(clock, rotateRefreshTokens, null);
    }

    private static Fixture createFixture(
            Clock clock, boolean rotateRefreshTokens, AccessTokenGenerator accessTokenGenerator) {
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
                rotateRefreshTokens,
                accessTokenGenerator);
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
    @Test
    void acceptsCaseInsensitiveBearerScheme() {
        Fixture fixture = createFixture(Clock.fixed(NOW, ZoneOffset.UTC), true);
        TokenResponse response = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        assertEquals(BearerAuthResult.OK,
                fixture.tokens.checkBearerAuth("bearer " + response.getAccessToken()));
    }

    @Test
    void rejectsDuplicateAccessTokenGeneratorValuesWithoutOverwritingExistingToken() {
        Fixture fixture = createFixture(
                Clock.fixed(NOW, ZoneOffset.UTC), true, () -> "fixed-access-token");
        TokenResponse first = fixture.tokens.exchangeAuthorizationCode(
                CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER);

        assertThrows(IllegalStateException.class, () ->
                fixture.tokens.exchangeAuthorizationCode(
                        CLIENT_ID, CLIENT_SECRET, fixture.issueCode(), REDIRECT_URI, VERIFIER));

        assertEquals(BearerAuthResult.OK,
                fixture.tokens.checkBearerAuth("Bearer " + first.getAccessToken()));
    }
}