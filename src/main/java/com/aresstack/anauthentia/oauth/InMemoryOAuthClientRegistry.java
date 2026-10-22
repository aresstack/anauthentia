package com.aresstack.anauthentia.oauth;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Process-local client registry for tests and simple single-instance deployments.
 */
public final class InMemoryOAuthClientRegistry implements OAuthClientRegistry {

    private final ConcurrentMap<String, OAuthClient> clients = new ConcurrentHashMap<String, OAuthClient>();

    public void register(OAuthClient client) {
        if (client == null) {
            throw new IllegalArgumentException("client must not be null");
        }
        OAuthClient previous = clients.putIfAbsent(client.getClientId(), client);
        if (previous != null) {
            throw new IllegalArgumentException("Client is already registered: " + client.getClientId());
        }
    }

    @Override
    public Optional<OAuthClient> findByClientId(String clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(clients.get(clientId));
    }
}
