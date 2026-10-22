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
    private final Instant expiresAt;

    public AuthorizationCode(String clientId, String redirectUri, String codeChallenge, Instant expiresAt) {
        this(clientId, redirectUri, "mcp", codeChallenge, expiresAt);
    }

    public AuthorizationCode(
            String clientId,
            String redirectUri,
            String scope,
            String codeChallenge,
            Instant expiresAt) {
        this.clientId = requireText(clientId, "clientId");
        this.redirectUri = requireText(redirectUri, "redirectUri");
        this.scope = requireText(scope, "scope");
        this.codeChallenge = codeChallenge;
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

    public Instant getExpiresAt() {
        return expiresAt;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}