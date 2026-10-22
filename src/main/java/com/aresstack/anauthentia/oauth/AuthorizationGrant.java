package com.aresstack.anauthentia.oauth;

/**
 * Result of a successfully validated and consumed authorization code.
 *
 * <p>This value does not contain an access token. The HTTP adapter can issue
 * tokens only after the code exchange succeeds.
 */
public final class AuthorizationGrant {

    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private final String resource;

    public AuthorizationGrant(String clientId, String redirectUri) {
        this(clientId, redirectUri, "mcp");
    }

    public AuthorizationGrant(String clientId, String redirectUri, String scope) {
        this(clientId, redirectUri, scope, null);
    }

    public AuthorizationGrant(String clientId, String redirectUri, String scope, String resource) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.resource = resource;
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

    /** RFC 8707 target resource the grant is bound to, or {@code null}. */
    public String getResource() {
        return resource;
    }
}