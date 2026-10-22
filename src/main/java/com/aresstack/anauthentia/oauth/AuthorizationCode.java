package com.aresstack.anauthentia.oauth;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable authorization-code data managed by a host application using this library.
 * A missing PKCE challenge is only valid when the owning service explicitly allows it.
 */
public final class AuthorizationCode {

    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final String codeChallenge;
    private final String codeChallengeMethod;
    private final String resource;
    private final Instant expiresAt;

    public AuthorizationCode(String clientId, String redirectUri, String codeChallenge, Instant expiresAt) {
        this(clientId, redirectUri, "mcp", codeChallenge, defaultMethod(codeChallenge), expiresAt);
    }

    public AuthorizationCode(
            String clientId,
            String redirectUri,
            String scope,
            String codeChallenge,
            Instant expiresAt) {
        this(clientId, redirectUri, scope, codeChallenge, defaultMethod(codeChallenge), expiresAt);
    }

    public AuthorizationCode(
            String clientId,
            String redirectUri,
            String scope,
            String codeChallenge,
            String codeChallengeMethod,
            Instant expiresAt) {
        this(clientId, redirectUri, scope, codeChallenge, codeChallengeMethod, null, expiresAt);
    }

    public AuthorizationCode(
            String clientId,
            String redirectUri,
            String scope,
            String codeChallenge,
            String codeChallengeMethod,
            String resource,
            Instant expiresAt) {
        this.resource = resource == null || resource.trim().isEmpty() ? null : resource.trim();
        this.clientId = requireText(clientId, "clientId");
        this.redirectUri = requireText(redirectUri, "redirectUri");
        this.scope = requireText(scope, "scope");
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** RFC 8707 target resource the grant is bound to, or {@code null}. */
    public String getResource() {
        return resource;
    }

    private static String defaultMethod(String codeChallenge) {
        return codeChallenge == null || codeChallenge.trim().isEmpty() ? null : "S256";
    }

    private static String requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}