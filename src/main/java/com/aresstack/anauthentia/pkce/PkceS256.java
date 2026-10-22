package com.aresstack.anauthentia.pkce;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Stateless RFC 7636 PKCE S256 validation.
 *
 * <p>This class deliberately does not accept the {@code plain} code challenge method.
 * The host application's OAuth flow is responsible for requiring and storing the
 * challenge together with the authorization code.
 */
public final class PkceS256 {

    private static final int MIN_VERIFIER_LENGTH = 43;
    private static final int MAX_VERIFIER_LENGTH = 128;
    private static final int CHALLENGE_LENGTH = 43;

    private PkceS256() {
    }

    /**
     * Verifies a challenge without logging or exposing the code verifier.
     * Invalid or missing inputs never authorize a request.
     *
     * @param verifier the client's PKCE code verifier
     * @param expectedChallenge the challenge bound to the authorization code
     * @return {@code true} only for a valid matching S256 challenge
     */
    public static boolean matches(String verifier, String expectedChallenge) {
        if (!isValidVerifier(verifier) || !isValidChallenge(expectedChallenge)) {
            return false;
        }
        byte[] actual = calculateChallenge(verifier).getBytes(StandardCharsets.US_ASCII);
        byte[] expected = expectedChallenge.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(actual, expected);
    }

    private static String calculateChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static boolean isValidVerifier(String verifier) {
        if (verifier == null || verifier.length() < MIN_VERIFIER_LENGTH || verifier.length() > MAX_VERIFIER_LENGTH) {
            return false;
        }
        for (int i = 0; i < verifier.length(); i++) {
            char value = verifier.charAt(i);
            if (!isAlphaNumeric(value) && value != '-' && value != '.' && value != '_' && value != '~') {
                return false;
            }
        }
        return true;
    }

    private static boolean isValidChallenge(String challenge) {
        if (challenge == null || challenge.length() != CHALLENGE_LENGTH) {
            return false;
        }
        for (int i = 0; i < challenge.length(); i++) {
            char value = challenge.charAt(i);
            if (!isAlphaNumeric(value) && value != '-' && value != '_') {
                return false;
            }
        }
        return true;
    }

    private static boolean isAlphaNumeric(char value) {
        return (value >= 'a' && value <= 'z')
                || (value >= 'A' && value <= 'Z')
                || (value >= '0' && value <= '9');
    }
}
