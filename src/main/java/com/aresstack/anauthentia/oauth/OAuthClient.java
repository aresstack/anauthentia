package com.aresstack.anauthentia.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Immutable client registration with an exact redirect URI allow-list.
 *
 * <p>Use a null or empty secret only for a public client that relies on PKCE.
 * Store confidential-client secrets in the host application's secret store.
 */
public final class OAuthClient {

    private final String clientId;
    private final String clientSecret;
    private final Set<String> redirectUris;

    public OAuthClient(String clientId, Set<String> redirectUris) {
        this(clientId, null, redirectUris);
    }

    /**
     * Register a client whose redirect URIs are validated by a host-supplied policy.
     */
    public static OAuthClient withHostManagedRedirects(String clientId, String clientSecret) {
        return new OAuthClient(clientId, clientSecret, Collections.<String>emptySet(), true);
    }

    public OAuthClient(String clientId, String clientSecret, Set<String> redirectUris) {
        this(clientId, clientSecret, redirectUris, false);
    }

    private OAuthClient(
            String clientId, String clientSecret, Set<String> redirectUris, boolean allowEmptyRedirectUris) {
        if (isBlank(clientId)) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        if (redirectUris == null || (!allowEmptyRedirectUris && redirectUris.isEmpty())) {
            throw new IllegalArgumentException("At least one redirect URI is required");
        }
        Set<String> validatedRedirectUris = new HashSet<String>();
        for (String redirectUri : redirectUris) {
            if (isBlank(redirectUri)) {
                throw new IllegalArgumentException("redirect URIs must not be blank");
            }
            validatedRedirectUris.add(redirectUri);
        }
        this.clientId = clientId;
        this.clientSecret = isBlank(clientSecret) ? null : clientSecret;
        this.redirectUris = Collections.unmodifiableSet(validatedRedirectUris);
    }

    public String getClientId() {
        return clientId;
    }

    public boolean allowsRedirectUri(String redirectUri) {
        return redirectUris.contains(redirectUri);
    }

    public boolean hasClientSecret() {
        return clientSecret != null;
    }

    /**
     * Compare confidential-client secrets without a content-dependent early exit.
     */
    public boolean authenticatesSecret(String suppliedSecret) {
        if (clientSecret == null) {
            return isBlank(suppliedSecret);
        }
        if (suppliedSecret == null) {
            return false;
        }
        return MessageDigest.isEqual(
                clientSecret.getBytes(StandardCharsets.UTF_8),
                suppliedSecret.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}