package com.aresstack.anauthentia.oauth;

import java.util.Map;

/**
 * Persistence boundary for refresh tokens.
 *
 * <p>Implementations must make each load or save operation thread-safe. Save
 * replaces the complete snapshot, allowing applications to use their own
 * atomic file, database, or distributed-store strategy without a library
 * dependency on a persistence framework.
 */
public interface RefreshTokenStore {

    Map<String, RefreshToken> load();

    void save(Map<String, RefreshToken> tokens);
}