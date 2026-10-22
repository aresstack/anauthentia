package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthorizationRequestTest {

    private static final String CLIENT_ID = "test-client";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void validatesRequestAndPreservesStateAndScope() {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService service = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC),
                Duration.ofMinutes(5));

        String location = service.authorize(
                "code", CLIENT_ID, REDIRECT_URI, "state value", "mcp", CHALLENGE, "S256");

        assertTrue(location.startsWith(REDIRECT_URI + "?code="));
        assertTrue(location.contains("&state=state%20value"));
    }

    @Test
    void rejectsUnsupportedResponseType() {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService service = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                Clock.systemUTC(),
                Duration.ofMinutes(5));

        OAuthException exception = assertThrows(OAuthException.class, () ->
                service.authorize("token", CLIENT_ID, REDIRECT_URI, null, "mcp", CHALLENGE, "S256"));

        assertTrue("unsupported_response_type".equals(exception.getError()));
    }

    @Test
    void requiresPkceS256() {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(CLIENT_ID, Collections.singleton(REDIRECT_URI)));
        AuthorizationCodeService service = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                new SecureRandom(),
                Clock.systemUTC(),
                Duration.ofMinutes(5));

        OAuthException exception = assertThrows(OAuthException.class, () ->
                service.authorize("code", CLIENT_ID, REDIRECT_URI, null, "mcp", CHALLENGE, "plain"));

        assertTrue("invalid_request".equals(exception.getError()));
    }
}