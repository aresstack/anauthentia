package com.aresstack.anauthentia.oauth;

/**
 * OAuth token response data independent of JSON or HTTP libraries.
 */
public final class TokenResponse {

    private final String accessToken;
    private final String tokenType;
    private final int expiresIn;
    private final String refreshToken;
    private final String scope;

    public TokenResponse(String accessToken, String tokenType, int expiresIn, String refreshToken, String scope) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.refreshToken = refreshToken;
        this.scope = scope;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getScope() {
        return scope;
    }
}