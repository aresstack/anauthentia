package com.aresstack.anauthentia.oauth;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable refresh-token state suitable for host-provided persistence.
 */
public final class RefreshToken {

    private final String clientId;
    private final String scope;
    private final String resource;
    private final Instant expiresAt;

    public RefreshToken(String clientId, String scope, Instant expiresAt) {
        this(clientId, scope, null, expiresAt);
    }

    public RefreshToken(String clientId, String scope, String resource, Instant expiresAt) {
        this.clientId = requireText(clientId, "clientId");
        this.scope = requireText(scope, "scope");
        this.resource = resource == null || resource.trim().isEmpty() ? null : resource.trim();
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public String getClientId() {
        return clientId;
    }

    public String getScope() {
        return scope;
    }

    /** RFC 8707 target resource this refresh token is bound to, or {@code null}. */
    public String getResource() {
        return resource;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof RefreshToken)) {
            return false;
        }
        RefreshToken that = (RefreshToken) other;
        return clientId.equals(that.clientId)
                && scope.equals(that.scope)
                && Objects.equals(resource, that.resource)
                && expiresAt.equals(that.expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, scope, resource, expiresAt);
    }

    private static String requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}