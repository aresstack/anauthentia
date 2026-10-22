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
    private static final String TOKEN_DIGEST_PREFIX = "s256:";
    private static final Duration ACCESS_TOKEN_CLEANUP_INTERVAL = Duration.ofMinutes(1);
    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthorizationCodeService authorizationCodeService;
    private final OAuthClientRegistry clientRegistry;
    private final RefreshTokenStore refreshTokenStore;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration accessTokenLifetime;
    private final Duration refreshTokenLifetime;
    private final boolean refreshTokenRotationEnabled;
    private final GrantAwareAccessTokenGenerator accessTokenGenerator;
    private final Map<String, AccessTokenState> accessTokens = new HashMap<String, AccessTokenState>();
    private Instant nextAccessTokenCleanup = Instant.MIN;
    private final Map<String, RefreshToken> refreshTokens = new HashMap<String, RefreshToken>();
    private final Map<String, AuthorizationReplay> authorizationReplayCache =
            new HashMap<String, AuthorizationReplay>();
    private final Map<String, RefreshReplay> refreshReplayCache = new HashMap<String, RefreshReplay>();

    /** Create a token service using cryptographically random opaque access tokens. */
    public OAuthTokenService(
            AuthorizationCodeService authorizationCodeService,
            OAuthClientRegistry clientRegistry,
            RefreshTokenStore refreshTokenStore,
            SecureRandom secureRandom,
            Clock clock,
            Duration accessTokenLifetime,
            Duration refreshTokenLifetime,
            boolean refreshTokenRotationEnabled) {
        this(authorizationCodeService, clientRegistry, refreshTokenStore, secureRandom, clock,
                accessTokenLifetime, refreshTokenLifetime, refreshTokenRotationEnabled,
                (AccessTokenGenerator) null);
    }

    /** Create a token service with an optional host-supplied access-token generator. */
    public OAuthTokenService(
            AuthorizationCodeService authorizationCodeService,
            OAuthClientRegistry clientRegistry,
            RefreshTokenStore refreshTokenStore,
            SecureRandom secureRandom,
            Clock clock,
            Duration accessTokenLifetime,
            Duration refreshTokenLifetime,
            boolean refreshTokenRotationEnabled,
            AccessTokenGenerator accessTokenGenerator) {
        this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService, "authorizationCodeService");
        this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry");
        this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore, "refreshTokenStore");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.accessTokenLifetime = requirePositiveLifetime(accessTokenLifetime, "accessTokenLifetime");
        this.refreshTokenLifetime = requirePositiveLifetime(refreshTokenLifetime, "refreshTokenLifetime");
        this.refreshTokenRotationEnabled = refreshTokenRotationEnabled;
        AccessTokenGenerator plainGenerator =
                accessTokenGenerator == null ? this::createOpaqueValue : accessTokenGenerator;
        this.accessTokenGenerator =
                (clientId, scope, resource, issuedAt, expiresAt) -> plainGenerator.generate();
        loadRefreshTokens();
        removeExpiredRefreshTokens();
    }

    /** Create a token service whose access tokens embed grant context (e.g. signed JWTs). */
    public OAuthTokenService(
            AuthorizationCodeService authorizationCodeService,
            OAuthClientRegistry clientRegistry,
            RefreshTokenStore refreshTokenStore,
            SecureRandom secureRandom,
            Clock clock,
            Duration accessTokenLifetime,
            Duration refreshTokenLifetime,
            boolean refreshTokenRotationEnabled,
            GrantAwareAccessTokenGenerator accessTokenGenerator) {
        this.authorizationCodeService = Objects.requireNonNull(authorizationCodeService, "authorizationCodeService");
        this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry");
        this.refreshTokenStore = Objects.requireNonNull(refreshTokenStore, "refreshTokenStore");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.accessTokenLifetime = requirePositiveLifetime(accessTokenLifetime, "accessTokenLifetime");
        this.refreshTokenLifetime = requirePositiveLifetime(refreshTokenLifetime, "refreshTokenLifetime");
        this.refreshTokenRotationEnabled = refreshTokenRotationEnabled;
        this.accessTokenGenerator = Objects.requireNonNull(accessTokenGenerator, "accessTokenGenerator");
        loadRefreshTokens();
        removeExpiredRefreshTokens();
    }

    /**
     * Dispatch a token grant after authenticating the OAuth client.
     */
    public synchronized TokenResponse exchangeToken(
            String clientId,
            String clientSecret,
            String grantType,
            String code,
            String refreshToken,
            String redirectUri,
            String codeVerifier) {
        return exchangeToken(clientId, clientSecret, grantType, code, refreshToken,
                redirectUri, codeVerifier, null);
    }

    /**
     * Dispatch a token grant bound to an RFC 8707 target resource: the grant
     * must have been issued for this resource (or carry none), and the minted
     * access token embeds it.
     */
    public synchronized TokenResponse exchangeToken(
            String clientId,
            String clientSecret,
            String grantType,
            String code,
            String refreshToken,
            String redirectUri,
            String codeVerifier,
            String expectedResource) {
        if ("authorization_code".equals(grantType)) {
            return exchangeAuthorizationCode(clientId, clientSecret, code, redirectUri,
                    codeVerifier, expectedResource);
        }
        if ("refresh_token".equals(grantType)) {
            return refreshAccessToken(clientId, clientSecret, refreshToken, expectedResource);
        }
        authenticateClient(clientId, clientSecret);
        throw new OAuthException(400, "unsupported_grant_type");
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
        return exchangeAuthorizationCode(clientId, clientSecret, code, redirectUri, codeVerifier, null);
    }

    public synchronized TokenResponse exchangeAuthorizationCode(
            String clientId,
            String clientSecret,
            String code,
            String redirectUri,
            String codeVerifier,
            String expectedResource) {
        authenticateClient(clientId, clientSecret);
        cleanupReplayCaches();
        cleanupExpiredAccessTokens();

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
        // Resource binding: a code issued for resource A must never mint
        // tokens at resource B.
        String grantResource = grant.get().getResource();
        if (grantResource != null && expectedResource != null
                && !grantResource.equals(expectedResource)) {
            throw new OAuthException(400, "invalid_grant");
        }
        String resource = grantResource != null ? grantResource : expectedResource;

        Instant now = clock.instant();
        String accessToken = generateAccessToken(
                clientId, grant.get().getScope(), resource, now, now.plus(accessTokenLifetime));
        String refreshToken = createOpaqueValue();
        int expiresIn = toSeconds(accessTokenLifetime);

        Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
        nextRefreshTokens.put(digestToken(refreshToken), new RefreshToken(
                clientId, grant.get().getScope(), resource, now.plus(refreshTokenLifetime)));
        replaceRefreshTokens(nextRefreshTokens);

        accessTokens.put(accessToken, new AccessTokenState(clientId, grant.get().getScope(), now.plus(accessTokenLifetime)));
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
        return refreshAccessToken(clientId, clientSecret, refreshToken, null);
    }

    public synchronized TokenResponse refreshAccessToken(
            String clientId,
            String clientSecret,
            String refreshToken,
            String expectedResource) {
        authenticateClient(clientId, clientSecret);
        cleanupReplayCaches();
        cleanupExpiredAccessTokens();
        removeExpiredRefreshTokens();
        if (isBlank(refreshToken)) {
            throw new OAuthException(400, "invalid_grant");
        }

        String refreshTokenKey = digestToken(refreshToken);
        RefreshToken state = refreshTokens.get(refreshTokenKey);
        if (state == null) {
            RefreshReplay replay = refreshReplayCache.get(refreshTokenKey);
            if (replay != null && replay.clientId.equals(clientId)) {
                return replay.response;
            }
            throw new OAuthException(400, "invalid_grant");
        }
        if (!state.getClientId().equals(clientId)) {
            throw new OAuthException(400, "invalid_grant");
        }
        // Resource binding: a refresh token of resource A never refreshes at B.
        if (state.getResource() != null && expectedResource != null
                && !state.getResource().equals(expectedResource)) {
            throw new OAuthException(400, "invalid_grant");
        }
        String resource = state.getResource() != null ? state.getResource() : expectedResource;
        if (!state.getExpiresAt().isAfter(clock.instant())) {
            Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
            nextRefreshTokens.remove(refreshTokenKey);
            replaceRefreshTokens(nextRefreshTokens);
            throw new OAuthException(400, "invalid_grant");
        }

        Instant now = clock.instant();
        String accessToken = generateAccessToken(
                clientId, state.getScope(), resource, now, now.plus(accessTokenLifetime));
        String nextRefreshToken = refreshToken;
        if (refreshTokenRotationEnabled) {
            nextRefreshToken = createOpaqueValue();
            Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
            nextRefreshTokens.remove(refreshTokenKey);
            nextRefreshTokens.put(digestToken(nextRefreshToken), new RefreshToken(
                    clientId, state.getScope(), resource, now.plus(refreshTokenLifetime)));
            replaceRefreshTokens(nextRefreshTokens);
        }

        accessTokens.put(accessToken, new AccessTokenState(clientId, state.getScope(), now.plus(accessTokenLifetime)));
        TokenResponse response = new TokenResponse(
                accessToken, "Bearer", toSeconds(accessTokenLifetime), nextRefreshToken, state.getScope());
        if (refreshTokenRotationEnabled) {
            refreshReplayCache.put(refreshTokenKey, new RefreshReplay(
                    clientId, response, now.plus(REPLAY_WINDOW)));
        }
        return response;
    }

    /**
     * Revoke a refresh token (RFC 7009 semantics): the client must
     * authenticate, revoking succeeds silently for unknown or foreign tokens
     * so callers cannot probe token existence, and a revoked token is removed
     * from the persistent store before this method returns.
     */
    public synchronized void revokeRefreshToken(
            String clientId, String clientSecret, String refreshToken) {
        authenticateClient(clientId, clientSecret);
        if (isBlank(refreshToken)) {
            return;
        }
        String refreshTokenKey = digestToken(refreshToken);
        refreshReplayCache.remove(refreshTokenKey);
        RefreshToken state = refreshTokens.get(refreshTokenKey);
        if (state == null || !state.getClientId().equals(clientId)) {
            return;
        }
        Map<String, RefreshToken> nextRefreshTokens = new HashMap<String, RefreshToken>(refreshTokens);
        nextRefreshTokens.remove(refreshTokenKey);
        replaceRefreshTokens(nextRefreshTokens);
    }

    /**
     * Validate an Authorization header without exposing token state.
     */
    public synchronized BearerAuthResult checkBearerAuth(String authorizationHeader) {
        String token = extractBearerToken(authorizationHeader);
        if (token == null) {
            return BearerAuthResult.MISSING_TOKEN;
        }

        AccessTokenState state = accessTokens.get(token);
        if (state == null) {
            cleanupExpiredAccessTokens();
            return BearerAuthResult.INVALID_TOKEN;
        }
        if (!state.expiresAt.isAfter(clock.instant())) {
            accessTokens.remove(token);
            cleanupExpiredAccessTokens();
            return BearerAuthResult.EXPIRED_TOKEN;
        }
        cleanupExpiredAccessTokens();
        return BearerAuthResult.OK;
    }

    /**
     * Resolve the authenticated client and granted scopes for a valid bearer token.
     */
    public synchronized Optional<BearerTokenPrincipal> resolveBearerToken(String authorizationHeader) {
        if (checkBearerAuth(authorizationHeader) != BearerAuthResult.OK) {
            return Optional.empty();
        }

        String token = extractBearerToken(authorizationHeader);
        AccessTokenState state = accessTokens.get(token);
        if (state == null) {
            return Optional.empty();
        }
        return Optional.of(new BearerTokenPrincipal(state.clientId, state.scope, state.expiresAt));
    }

    /** Return whether the supplied bearer token is valid and unexpired. */
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
                    // Ältere Stores enthalten Klartext-Tokens; beim Laden auf
                    // die gehashte Form migrieren (persistiert beim nächsten save).
                    String key = entry.getKey().startsWith(TOKEN_DIGEST_PREFIX)
                            ? entry.getKey() : digestToken(entry.getKey());
                    refreshTokens.put(key, entry.getValue());
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

    private void cleanupExpiredAccessTokens() {
        Instant now = clock.instant();
        if (now.isBefore(nextAccessTokenCleanup)) {
            return;
        }

        Iterator<Map.Entry<String, AccessTokenState>> iterator = accessTokens.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!iterator.next().getValue().expiresAt.isAfter(now)) {
                iterator.remove();
            }
        }
        nextAccessTokenCleanup = now.plus(ACCESS_TOKEN_CLEANUP_INTERVAL);
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

    private String generateAccessToken(
            String clientId, String scope, String resource, Instant issuedAt, Instant expiresAt) {
        String accessToken = accessTokenGenerator.generate(
                clientId, scope, resource, issuedAt, expiresAt);
        if (!isValidBearerTokenValue(accessToken)) {
            throw new IllegalStateException("Access-token generator returned an invalid bearer-token value");
        }
        if (accessTokens.containsKey(accessToken)) {
            throw new IllegalStateException("Access-token generator returned a duplicate value");
        }
        return accessToken;
    }

    private static boolean isValidBearerTokenValue(String token) {
        if (isBlank(token)) {
            return false;
        }
        boolean paddingStarted = false;
        boolean tokenCharacterSeen = false;
        for (int index = 0; index < token.length(); index++) {
            char character = token.charAt(index);
            if (character == '=') {
                if (!tokenCharacterSeen) {
                    return false;
                }
                paddingStarted = true;
            } else if (isBearerTokenCharacter(character) && !paddingStarted) {
                tokenCharacterSeen = true;
            } else {
                return false;
            }
        }
        return tokenCharacterSeen;
    }

    private static boolean isBearerTokenCharacter(char character) {
        return (character >= 'a' && character <= 'z')
                || (character >= 'A' && character <= 'Z')
                || (character >= '0' && character <= '9')
                || character == '-'
                || character == '.'
                || character == '_'
                || character == '~'
                || character == '+'
                || character == '/';
    }

    private static String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null
                || authorizationHeader.length() <= BEARER_PREFIX.length()
                || !authorizationHeader.regionMatches(true, 0, "Bearer", 0, "Bearer".length())
                || authorizationHeader.charAt("Bearer".length()) != ' ') {
            return null;
        }
        String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
        return isBlank(token) ? null : token;
    }

    /**
     * Store refresh tokens only as salted-free SHA-256 digests: a leaked store
     * file must not yield usable credentials. Tokens are 256-bit random values,
     * so a plain digest is preimage-resistant without a salt.
     */
    private static String digestToken(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return TOKEN_DIGEST_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
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
        private final String clientId;
        private final String scope;
        private final Instant expiresAt;

        private AccessTokenState(String clientId, String scope, Instant expiresAt) {
            this.clientId = clientId;
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