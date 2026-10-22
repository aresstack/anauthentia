package com.aresstack.anauthentia.oauth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Process-local refresh-token store for tests and single-process use.
 */
public final class InMemoryRefreshTokenStore implements RefreshTokenStore {

    private Map<String, RefreshToken> tokens = new LinkedHashMap<String, RefreshToken>();

    @Override
    public synchronized Map<String, RefreshToken> load() {
        return new LinkedHashMap<String, RefreshToken>(tokens);
    }

    @Override
    public synchronized void save(Map<String, RefreshToken> tokens) {
        if (tokens == null) {
            throw new IllegalArgumentException("tokens must not be null");
        }
        this.tokens = new LinkedHashMap<String, RefreshToken>(tokens);
    }
}