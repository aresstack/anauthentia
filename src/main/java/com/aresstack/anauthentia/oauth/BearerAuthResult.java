package com.aresstack.anauthentia.oauth;

/**
 * Result of validating an OAuth Bearer authorization header.
 */
public enum BearerAuthResult {
    MISSING_TOKEN,
    INVALID_TOKEN,
    EXPIRED_TOKEN,
    OK
}