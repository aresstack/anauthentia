package com.aresstack.anauthentia.jwt;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/** Validated claims of an accepted RFC 9068 access token. */
public final class JwtAccessToken {

    private final String clientId;
    private final String scope;
    private final Instant expiresAt;
    private final String tokenId;

    JwtAccessToken(String clientId, String scope, Instant expiresAt, String tokenId) {
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.scope = scope == null ? "" : scope;
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.tokenId = tokenId;
    }

    public String getClientId() {
        return clientId;
    }

    /** Space-separated granted scopes, possibly empty. */
    public String getScope() {
        return scope;
    }

    public Set<String> getScopes() {
        if (scope.trim().isEmpty()) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(
                new LinkedHashSet<String>(Arrays.asList(scope.trim().split(" "))));
    }

    public boolean hasScope(String required) {
        return getScopes().contains(required);
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** The {@code jti} claim, or {@code null} if absent. */
    public String getTokenId() {
        return tokenId;
    }
}
