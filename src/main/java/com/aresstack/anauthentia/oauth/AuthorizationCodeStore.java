package com.aresstack.anauthentia.oauth;

/**
 * Store authorization codes with atomic, one-time consumption semantics.
 */
public interface AuthorizationCodeStore {

    /**
     * Store a new authorization code.
     *
     * @param value opaque code sent to the client
     * @param authorizationCode immutable code data
     * @return true if the value was new, false if it already existed
     */
    boolean putIfAbsent(String value, AuthorizationCode authorizationCode);

    /**
     * Atomically remove and return a code so it cannot be exchanged twice.
     *
     * @param value opaque code sent by the client
     * @return the removed code, or null if it is unknown or already consumed
     */
    AuthorizationCode consume(String value);
}
