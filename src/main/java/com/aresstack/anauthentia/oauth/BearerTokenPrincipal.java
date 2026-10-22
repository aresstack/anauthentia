package com.aresstack.anauthentia.oauth;

import java.time.Instant;
import java.util.Objects;

/** Represent the identity and granted scopes associated with a validated bearer token. */
public final class BearerTokenPrincipal {

    private final String clientId;
    private final String scope;
    private final Instant expiresAt;

    BearerTokenPrincipal(String clientId, String scope, Instant expiresAt) {
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.scope = Objects.requireNonNull(scope, "scope");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
    }

    /** Return the client identifier bound to the token. */
    public String getClientId() {
        return clientId;
    }

    /** Return the scope string granted to the token. */
    public String getScope() {
        return scope;
    }

    /** Return the token expiration instant. */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** Return whether the granted scope contains the requested single scope token. */
    public boolean includesScope(String requestedScope) {
        if (requestedScope == null || requestedScope.trim().isEmpty() || requestedScope.indexOf(' ') >= 0) {
            return false;
        }
        for (String grantedScope : scope.split(" ")) {
            if (grantedScope.equals(requestedScope)) {
                return true;
            }
        }
        return false;
    }
}
