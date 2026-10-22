package com.aresstack.anauthentia.oauth;

import java.util.Optional;

/**
 * Resolve registered OAuth clients without coupling the core to a persistence technology.
 */
public interface OAuthClientRegistry {

    Optional<OAuthClient> findByClientId(String clientId);
}
