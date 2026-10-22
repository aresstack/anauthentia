package com.aresstack.anauthentia.pkce;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PkceS256Test {

    private static final String RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void acceptsRfc7636S256TestVector() {
        assertTrue(PkceS256.matches(RFC7636_VERIFIER, RFC7636_CHALLENGE));
    }

    @Test
    void rejectsDifferentVerifier() {
        assertFalse(PkceS256.matches(RFC7636_VERIFIER + "x", RFC7636_CHALLENGE));
    }

    @Test
    void rejectsMissingVerifierOrChallenge() {
        assertFalse(PkceS256.matches(null, RFC7636_CHALLENGE));
        assertFalse(PkceS256.matches(RFC7636_VERIFIER, null));
    }

    @Test
    void rejectsShortInvalidOrPaddedInputs() {
        assertFalse(PkceS256.matches("short", RFC7636_CHALLENGE));
        assertFalse(PkceS256.matches(RFC7636_VERIFIER + " ", RFC7636_CHALLENGE));
        assertFalse(PkceS256.matches(RFC7636_VERIFIER, RFC7636_CHALLENGE + "="));
    }
}
