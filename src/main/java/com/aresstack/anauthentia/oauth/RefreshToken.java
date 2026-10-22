package com.aresstack.anauthentia.oauth;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable refresh-token state suitable for host-provided persistence.
 */
public final class RefreshToken {

    private final String clientId;
    private final String scope;
    private final Instant expiresAt;

    public RefreshToken(String clientId, String scope, Instant expiresAt) {
        this.clientId = requireText(clientId, "clientId");
        this.scope = requireText(scope, "scope");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public String getClientId() {
        return clientId;
    }

    public String getScope() {
        return scope;
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
                && expiresAt.equals(that.expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, scope, expiresAt);
    }

    private static String requireText(String value, String name) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}