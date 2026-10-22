package com.aresstack.anauthentia.oauth;

/**
 * Host-supplied policy for validating OAuth redirect URIs.
 *
 * <p>The default policy should use the exact URI allow-list on the client.
 * Hosts may inject a stricter domain-specific policy when redirect URIs are
 * managed by an external authorization platform.
 */
public interface RedirectUriPolicy {

    boolean allows(OAuthClient client, String redirectUri);
}