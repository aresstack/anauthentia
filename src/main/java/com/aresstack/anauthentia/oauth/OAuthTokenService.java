package com.aresstack.anauthentia.oauth;


import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Framework-neutral OAuth token lifecycle built around the authorization-code
 * service and client registry.
 *
 * <p>Serialize state transitions so authorization-code exchange, refresh-token
 * rotation, and short replay windows behave predictably under parallel requests.
 * HTTP routing, protocol serialization, and durable storage remain host concerns.
 */
public final class OAuthTokenService {

    private static final Duration REPLAY_WINDOW = Duration.ofSeconds(10);
    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthorizationCodeService authorizationCodeService;
    private final OAuthClientRegistry clientRegistry;
    private final RefreshTokenStore refreshTokenStore;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration accessTokenLifetime;
    private final Duration refreshTokenLifetime;
    private final boolean refreshTokenRotationEnabled;
    private final Map<String, AccessTokenState> accessTokens = new HashMap<String, AccessTokenState>();
    private final Map<String, RefreshToken> refreshTokens = new HashMap<String, RefreshToken>();
    private final Map<String, AuthorizationReplay> authorizationReplayCache =
            new HashMap<String, AuthorizationReplay>();
    private final Map<String, RefreshReplay> refreshReplayCache = new HashMap<String, RefreshReplay>();

    public OAuthTokenService(
            AuthorizationCodeService authorizationCodeService,
            OAuthClientRegistry clientRegistry,
            RefreshTokenStore refreshTokenStore,
            SecureRandom secureRandom,
            Clock clock,
            Duration accessTokenLifetime,
            Duration refreshTokenLifetime,
            boolean refreshTokenRotationEnabled) {
        this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService, "authorizationCodeService");
        this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry");
        this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore, "refreshTokenStore");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.accessTokenLifetime = requirePositiveLifetime(accessTokenLifetime, "accessTokenLifetime");
        this.refreshTokenLifetime = requirePositiveLifetime(refreshTokenLifetime, "refreshTokenLifetime");
        this.refreshTokenRotationEnabled = refreshTokenRotationEnabled;
        loadRefreshTokens();
        removeExpiredRefreshTokens();
    }

    /**
     * Exchange a valid authorization code and tolerate an identical short-lived replay.
     */
    public synchronized TokenResponse exchangeAuthorizationCode(
            String clientId,
            String clientSecret,
            String code,
            String redirectUri,
            String codeVerifier) {
        authenticateClient(clientId, clientSecret);
        cleanupReplayCaches();

        AuthorizationReplay replay = authorizationReplayCache.get(code);
        if (replay != null) {
            if (replay.matches(clientId, redirectUri, codeVerifier)) {
                return replay.response;
            }
            throw new OAuthException(400, "invalid_grant");
        }

        Optional<AuthorizationGrant> grant = authorizationCodeService.exchange(
                code, clientId, redirectUri, codeVerifier);
        if (!grant.isPresent()) {
            throw new OAuthException(400, "invalid_grant");
        }

        Instant now = clock.instant();
        String accessToken = createOpaqueValue();
        String refreshToken = createOpaqueValue();
        int expiresIn = toSeconds(accessTokenLifetime);

        Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
        nextRefreshTokens.put(refreshToken, new RefreshToken(
                clientId, grant.get().getScope(), now.plus(refreshTokenLifetime)));
        replaceRefreshTokens(nextRefreshTokens);

        accessTokens.put(accessToken, new AccessTokenState(grant.get().getScope(), now.plus(accessTokenLifetime)));
        TokenResponse response = new TokenResponse(
                accessToken, "Bearer", expiresIn, refreshToken, grant.get().getScope());
        authorizationReplayCache.put(code, new AuthorizationReplay(
                clientId, redirectUri, codeVerifier, response, now.plus(REPLAY_WINDOW)));
        return response;
    }

    /**
     * Exchange a valid refresh token, rotating it when configured.
     */
    public synchronized TokenResponse refreshAccessToken(
            String clientId,
            String clientSecret,
            String refreshToken) {
        authenticateClient(clientId, clientSecret);
        cleanupReplayCaches();
        if (isBlank(refreshToken)) {
            throw new OAuthException(400, "invalid_grant");
        }

        RefreshToken state = refreshTokens.get(refreshToken);
        if (state == null) {
            RefreshReplay replay = refreshReplayCache.get(refreshToken);
            if (replay != null && replay.clientId.equals(clientId)) {
                return replay.response;
            }
            throw new OAuthException(400, "invalid_grant");
        }
        if (!state.getClientId().equals(clientId)) {
            throw new OAuthException(400, "invalid_grant");
        }
        if (!state.getExpiresAt().isAfter(clock.instant())) {
            Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
            nextRefreshTokens.remove(refreshToken);
            replaceRefreshTokens(nextRefreshTokens);
            throw new OAuthException(400, "invalid_grant");
        }

        Instant now = clock.instant();
        String accessToken = createOpaqueValue();
        String nextRefreshToken = refreshToken;
        if (refreshTokenRotationEnabled) {
            nextRefreshToken = createOpaqueValue();
            Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
            nextRefreshTokens.remove(refreshToken);
            nextRefreshTokens.put(nextRefreshToken, new RefreshToken(
                    clientId, state.getScope(), now.plus(refreshTokenLifetime)));
            replaceRefreshTokens(nextRefreshTokens);
        }

        accessTokens.put(accessToken, new AccessTokenState(state.getScope(), now.plus(accessTokenLifetime)));
        TokenResponse response = new TokenResponse(
                accessToken, "Bearer", toSeconds(accessTokenLifetime), nextRefreshToken, state.getScope());
        if (refreshTokenRotationEnabled) {
            refreshReplayCache.put(refreshToken, new RefreshReplay(
                    clientId, response, now.plus(REPLAY_WINDOW)));
        }
        return response;
    }

    /**
     * Validate an Authorization header without exposing token state.
     */
    public synchronized BearerAuthResult checkBearerAuth(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            return BearerAuthResult.MISSING_TOKEN;
        }
        String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
        if (isBlank(token)) {
            return BearerAuthResult.MISSING_TOKEN;
        }

        AccessTokenState state = accessTokens.get(token);
        if (state == null) {
            return BearerAuthResult.INVALID_TOKEN;
        }
        if (!state.expiresAt.isAfter(clock.instant())) {
            accessTokens.remove(token);
            return BearerAuthResult.EXPIRED_TOKEN;
        }
        return BearerAuthResult.OK;
    }

    public synchronized boolean isBearerAuthorized(String authorizationHeader) {
        return checkBearerAuth(authorizationHeader) == BearerAuthResult.OK;
    }

    private void authenticateClient(String clientId, String clientSecret) {
        OAuthClient client = clientRegistry.findByClientId(clientId).orElse(null);
        if (client == null || !client.authenticatesSecret(clientSecret)) {
            throw new OAuthException(401, "invalid_client");
        }
    }

    private void loadRefreshTokens() {
        Map<String, RefreshToken> loaded = refreshTokenStore.load();
        if (loaded != null) {
            for (Map.Entry<String, RefreshToken> entry : loaded.entrySet()) {
                if (!isBlank(entry.getKey()) && entry.getValue() != null) {
                    refreshTokens.put(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    private void removeExpiredRefreshTokens() {
        Instant now = clock.instant();
        Map<String, RefreshToken> activeTokens = new HashMap<String, RefreshToken>(refreshTokens);
        boolean removedExpiredTokens = activeTokens.entrySet().removeIf(
                entry -> !entry.getValue().getExpiresAt().isAfter(now));
        if (removedExpiredTokens) {
            replaceRefreshTokens(activeTokens);
        }
    }

    private void replaceRefreshTokens(Map<String, RefreshToken> nextTokens) {
        Map<String, RefreshToken> snapshot = Collections.unmodifiableMap(
                new HashMap<String, RefreshToken>(nextTokens));
        refreshTokenStore.save(snapshot);
        refreshTokens.clear();
        refreshTokens.putAll(snapshot);
    }

    private void cleanupReplayCaches() {
        Instant now = clock.instant();
        removeExpiredEntries(authorizationReplayCache, now);
        removeExpiredEntries(refreshReplayCache, now);
    }

    private static <T extends ExpiringEntry> void removeExpiredEntries(Map<String, T> entries, Instant now) {
        Iterator<Map.Entry<String, T>> iterator = entries.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!iterator.next().getValue().expiresAt().isAfter(now)) {
                iterator.remove();
            }
        }
    }

    private String createOpaqueValue() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private static int toSeconds(Duration duration) {
        long seconds = duration.getSeconds();
        if (seconds < 1 || seconds > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Token lifetime must fit a positive HTTP expires_in value");
        }
        return (int) seconds;
    }

    private static Duration requirePositiveLifetime(Duration lifetime, String name) {
        Objects.requireNonNull(lifetime, name);
        toSeconds(lifetime);
        return lifetime;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static final class AccessTokenState {
        private final String scope;
        private final Instant expiresAt;

        private AccessTokenState(String scope, Instant expiresAt) {
            this.scope = scope;
            this.expiresAt = expiresAt;
        }
    }

    private interface ExpiringEntry {
        Instant expiresAt();
    }

    private static final class AuthorizationReplay implements ExpiringEntry {
        private final String clientId;
        private final String redirectUri;
        private final String codeVerifier;
        private final TokenResponse response;
        private final Instant expiresAt;

        private AuthorizationReplay(
                String clientId, String redirectUri, String codeVerifier, TokenResponse response, Instant expiresAt) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.codeVerifier = codeVerifier;
            this.response = response;
            this.expiresAt = expiresAt;
        }

        private boolean matches(String clientId, String redirectUri, String codeVerifier) {
            return this.clientId.equals(clientId)
                    && Objects.equals(this.redirectUri, redirectUri)
                    && Objects.equals(this.codeVerifier, codeVerifier);
        }

        @Override
        public Instant expiresAt() {
            return expiresAt;
        }
    }

    private static final class RefreshReplay implements ExpiringEntry {
        private final String clientId;
        private final TokenResponse response;
        private final Instant expiresAt;

        private RefreshReplay(String clientId, TokenResponse response, Instant expiresAt) {
            this.clientId = clientId;
            this.response = response;
            this.expiresAt = expiresAt;
        }

        @Override
        public Instant expiresAt() {
            return expiresAt;
        }
    }
}