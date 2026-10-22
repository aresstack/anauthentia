package com.aresstack.anauthentia.oauth;

import com.aresstack.anauthentia.pkce.PkceS256;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Framework-neutral authorization-code issuance and validation.
 *
 * <p>Require PKCE S256 and exact redirect URI matching by default. Hosts may
 * explicitly enable missing or legacy plain-PKCE compatibility and supply a redirect policy.
 * Consume a code atomically before validating the exchange so no invalid attempt
 * can make the same code available for replay. This class deliberately does not
 * create access tokens or handle HTTP requests.
 */
public final class AuthorizationCodeService {

    private static final int CODE_BYTES = 32;
    private static final String DEFAULT_SCOPE = "mcp";

    private final AuthorizationCodeStore store;
    private final OAuthClientRegistry clientRegistry;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration codeLifetime;
    private final boolean allowLegacyPkce;
    private final RedirectUriPolicy redirectUriPolicy;

    public AuthorizationCodeService(
            AuthorizationCodeStore store,
            OAuthClientRegistry clientRegistry,
            SecureRandom secureRandom,
            Clock clock,
            Duration codeLifetime) {
        this(store, clientRegistry, secureRandom, clock, codeLifetime, false, OAuthClient::allowsRedirectUri);
    }

    public AuthorizationCodeService(
            AuthorizationCodeStore store,
            OAuthClientRegistry clientRegistry,
            SecureRandom secureRandom,
            Clock clock,
            Duration codeLifetime,
            boolean allowLegacyPkce,
            RedirectUriPolicy redirectUriPolicy) {
        this.store = Objects.requireNonNull(store, "store");
        this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.codeLifetime = requirePositiveLifetime(codeLifetime);
        this.allowLegacyPkce = allowLegacyPkce;
        this.redirectUriPolicy = Objects.requireNonNull(redirectUriPolicy, "redirectUriPolicy");
    }

    /**
     * Validate an authorization request, issue its code, and build the redirect URI.
     */
    public String authorize(
            String responseType,
            String clientId,
            String redirectUri,
            String state,
            String scope,
            String codeChallenge,
            String codeChallengeMethod) {
        if (!"code".equals(responseType)) {
            throw new OAuthException(400, "unsupported_response_type");
        }
        if (isBlank(clientId)) {
            throw new OAuthException(400, "invalid_request", "Missing client_id");
        }
        if (isBlank(redirectUri)) {
            throw new OAuthException(400, "invalid_request", "Missing redirect_uri");
        }
        if (!isValidPkceRequest(codeChallenge, codeChallengeMethod)) {
            throw new OAuthException(400, "invalid_request", "PKCE S256 is required");
        }

        OAuthClient client = clientRegistry.findByClientId(clientId).orElse(null);
        if (client == null) {
            throw new OAuthException(400, "invalid_client");
        }
        if (!redirectUriPolicy.allows(client, redirectUri)) {
            throw new OAuthException(400, "invalid_request", "Unsupported redirect_uri");
        }

        String code = issue(clientId, redirectUri, normalizeScope(scope), codeChallenge, codeChallengeMethod);
        return appendQuery(redirectUri, code, state);
    }

    /**
     * Issue an opaque, short-lived authorization code bound to a client,
     * exact redirect URI, and PKCE S256 challenge.
     */
    public String issue(String clientId, String redirectUri, String codeChallenge) {
        return issue(clientId, redirectUri, DEFAULT_SCOPE, codeChallenge);
    }

    /**
     * Issue an opaque, short-lived authorization code with an explicit scope.
     */
    public String issue(String clientId, String redirectUri, String scope, String codeChallenge) {
        return issue(clientId, redirectUri, scope, codeChallenge,
                isBlank(codeChallenge) ? null : "S256");
    }

    private String issue(
            String clientId,
            String redirectUri,
            String scope,
            String codeChallenge,
            String codeChallengeMethod) {
        if (!isValidPkceRequest(codeChallenge, codeChallengeMethod)) {
            throw new IllegalArgumentException("Invalid PKCE parameters");
        }
        OAuthClient client = clientRegistry.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client is not registered"));
        if (!redirectUriPolicy.allows(client, redirectUri)) {
            throw new IllegalArgumentException("Redirect URI is not registered for this client");
        }

        AuthorizationCode authorizationCode = new AuthorizationCode(
                clientId,
                redirectUri,
                normalizeScope(scope),
                codeChallenge,
                codeChallengeMethod,
                clock.instant().plus(codeLifetime));

        for (int attempt = 0; attempt < 5; attempt++) {
            String value = generateCode();
            if (store.putIfAbsent(value, authorizationCode)) {
                return value;
            }
        }
        throw new IllegalStateException("Unable to generate a unique authorization code");
    }

    /**
     * Validate and consume an authorization code exactly once.
     *
     * <p>Every exchange attempt consumes the code, including an invalid attempt.
     * Return an empty result for unknown, expired, mismatched, or invalid-PKCE
     * requests without disclosing which check failed.
     */
    public Optional<AuthorizationGrant> exchange(
            String code,
            String clientId,
            String redirectUri,
            String codeVerifier) {
        if (isBlank(code)) {
            return Optional.empty();
        }

        AuthorizationCode stored = store.consume(code);
        if (stored == null || stored.getExpiresAt().compareTo(clock.instant()) <= 0) {
            return Optional.empty();
        }
        if (!stored.getClientId().equals(clientId) || !stored.getRedirectUri().equals(redirectUri)) {
            return Optional.empty();
        }
        OAuthClient client = clientRegistry.findByClientId(clientId).orElse(null);
        if (client == null || !redirectUriPolicy.allows(client, redirectUri)) {
            return Optional.empty();
        }
        if (!isValidPkceExchange(codeVerifier, stored.getCodeChallenge(), stored.getCodeChallengeMethod())) {
            return Optional.empty();
        }
        return Optional.of(new AuthorizationGrant(stored.getClientId(), stored.getRedirectUri(), stored.getScope()));
    }

    private String generateCode() {
        byte[] randomBytes = new byte[CODE_BYTES];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private static String appendQuery(String redirectUri, String code, String state) {
        int fragmentIndex = redirectUri.indexOf('#');
        String baseUri = fragmentIndex < 0 ? redirectUri : redirectUri.substring(0, fragmentIndex);
        String fragment = fragmentIndex < 0 ? "" : redirectUri.substring(fragmentIndex);
        String separator = baseUri.contains("?") ? "&" : "?";
        StringBuilder result = new StringBuilder(baseUri)
                .append(separator)
                .append("code=")
                .append(urlEncode(code));
        if (!isBlank(state)) {
            result.append("&state=").append(urlEncode(state));
        }
        return result.append(fragment).toString();
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException exception) {
            throw new IllegalStateException("UTF-8 is required by the Java platform", exception);
        }
    }

    private static Duration requirePositiveLifetime(Duration lifetime) {
        Objects.requireNonNull(lifetime, "codeLifetime");
        if (lifetime.isZero() || lifetime.isNegative()) {
            throw new IllegalArgumentException("codeLifetime must be positive");
        }
        return lifetime;
    }

    private static String normalizeScope(String scope) {
        return isBlank(scope) ? DEFAULT_SCOPE : scope.trim();
    }

    private boolean isValidPkceRequest(String challenge, String method) {
        if (isBlank(challenge)) {
            return allowLegacyPkce;
        }
        if ("S256".equals(method)) {
            return isValidChallenge(challenge);
        }
        return allowLegacyPkce && (isBlank(method) || "plain".equals(method));
    }

    private boolean isValidPkceExchange(String verifier, String challenge, String method) {
        if (isBlank(challenge)) {
            return allowLegacyPkce;
        }
        if ("S256".equals(method)) {
            return PkceS256.matches(verifier, challenge);
        }
        return allowLegacyPkce
                && (isBlank(method) || "plain".equals(method))
                && Objects.equals(verifier, challenge);
    }

    private static boolean isValidChallenge(String challenge) {
        if (challenge == null || challenge.length() != 43) {
            return false;
        }
        for (int i = 0; i < challenge.length(); i++) {
            char value = challenge.charAt(i);
            boolean alphaNumeric = (value >= 'a' && value <= 'z')
                    || (value >= 'A' && value <= 'Z')
                    || (value >= '0' && value <= '9');
            if (!alphaNumeric && value != '-' && value != '_') {
                return false;
            }
        }
        return true;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}