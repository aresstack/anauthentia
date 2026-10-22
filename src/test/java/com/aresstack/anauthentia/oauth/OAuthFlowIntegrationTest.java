package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLDecoder;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuthFlowIntegrationTest {

    private static final String CLIENT_ID = "chatgpt";
    private static final String CLIENT_SECRET = "test-client-secret";
    private static final String REDIRECT_URI = "https://chatgpt.com/connector/oauth/example";
    private static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void completesAuthorizationTokenRefreshAndBearerValidationFlow() throws Exception {
        InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
        clients.register(new OAuthClient(
                CLIENT_ID,
                CLIENT_SECRET,
                Collections.singleton(REDIRECT_URI)));

        SecureRandom secureRandom = new SecureRandom();
        Clock clock = Clock.systemUTC();

        AuthorizationCodeService authorizationCodes = new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clients,
                secureRandom,
                clock,
                Duration.ofMinutes(5));

        OAuthTokenService tokens = new OAuthTokenService(
                authorizationCodes,
                clients,
                new InMemoryRefreshTokenStore(),
                secureRandom,
                clock,
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                true);

        String redirectUri = authorizationCodes.authorize(
                "code",
                CLIENT_ID,
                REDIRECT_URI,
                "integration-state",
                "mcp",
                CODE_CHALLENGE,
                "S256");

        assertTrue(redirectUri.startsWith(REDIRECT_URI + "?code="));
        assertTrue(redirectUri.contains("&state=integration-state"));

        String code = queryParameter(redirectUri, "code");
        TokenResponse issuedTokens = tokens.exchangeToken(
                CLIENT_ID,
                CLIENT_SECRET,
                "authorization_code",
                code,
                null,
                REDIRECT_URI,
                CODE_VERIFIER);

        assertEquals("Bearer", issuedTokens.getTokenType());
        assertEquals("mcp", issuedTokens.getScope());
        assertEquals(BearerAuthResult.OK,
                tokens.checkBearerAuth("Bearer " + issuedTokens.getAccessToken()));

        TokenResponse refreshedTokens = tokens.exchangeToken(
                CLIENT_ID,
                CLIENT_SECRET,
                "refresh_token",
                null,
                issuedTokens.getRefreshToken(),
                null,
                null);

        assertNotEquals(issuedTokens.getRefreshToken(), refreshedTokens.getRefreshToken());
        assertEquals("mcp", refreshedTokens.getScope());
        assertEquals(BearerAuthResult.OK,
                tokens.checkBearerAuth("Bearer " + refreshedTokens.getAccessToken()));
    }

    private static String queryParameter(String url, String parameterName) throws Exception {
        String query = URI.create(url).getRawQuery();
        if (query == null) {
            throw new IllegalArgumentException("Redirect URI does not contain a query");
        }

        for (String pair : query.split("&")) {
            int separator = pair.indexOf('=');
            if (separator < 0) {
                continue;
            }
            String name = URLDecoder.decode(pair.substring(0, separator), "UTF-8");
            if (parameterName.equals(name)) {
                return URLDecoder.decode(pair.substring(separator + 1), "UTF-8");
            }
        }

        throw new IllegalArgumentException("Redirect URI does not contain parameter: " + parameterName);
    }
}
