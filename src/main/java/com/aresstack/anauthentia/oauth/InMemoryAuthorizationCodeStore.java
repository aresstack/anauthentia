package com.aresstack.anauthentia.oauth;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Process-local authorization-code store for tests and single-process deployments.
 *
 * <p>Use a persistent shared implementation when codes must survive restarts or
 * multiple application instances.
 */
public final class InMemoryAuthorizationCodeStore implements AuthorizationCodeStore {

    private final ConcurrentMap<String, AuthorizationCode> codes = new ConcurrentHashMap<String, AuthorizationCode>();

    @Override
    public boolean putIfAbsent(String value, AuthorizationCode authorizationCode) {
        return codes.putIfAbsent(value, authorizationCode) == null;
    }

    @Override
    public AuthorizationCode consume(String value) {
        return codes.remove(value);
    }
}
