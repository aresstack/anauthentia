package com.aresstack.anauthentia.oauth;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationCodeServiceTest {

    private static final String CLIENT_ID = "test-client";
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void rejectsUnregisteredRedirectUriAtIssuance() {
        AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));

        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> service.issue(CLIENT_ID, REDIRECT_URI + "/", CHALLENGE));
    }

    @Test
    void rejectsMalformedPkceChallengeAtIssuance() {
        AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));

        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> service.issue(CLIENT_ID, REDIRECT_URI, "not-a-valid-challenge"));
    }

    @Test
    void exchangesValidCodeExactlyOnce() {
        AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));
        String code = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);

        Optional<AuthorizationGrant> grant = service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER);

        assertTrue(grant.isPresent());
        assertEquals(CLIENT_ID, grant.get().getClientId());
        assertEquals(REDIRECT_URI, grant.get().getRedirectUri());
        assertFalse(service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER).isPresent());
    }

    @Test
    void rejectsMismatchedClientAndRedirectUri() {
        AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));

        String clientMismatch = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        assertFalse(service.exchange(clientMismatch, "other-client", REDIRECT_URI, VERIFIER).isPresent());

        String redirectMismatch = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        assertFalse(service.exchange(redirectMismatch, CLIENT_ID, REDIRECT_URI + "/", VERIFIER).isPresent());
    }

    @Test
    void consumesCodeWhenPkceVerificationFails() {
        AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));
        String code = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);

        assertFalse(service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER + "x").isPresent());
        assertFalse(service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER).isPresent());
    }

    @Test
    void rejectsExpiredCode() {
        AtomicReference<Instant> now = new AtomicReference<Instant>(NOW);
        Clock clock = new MutableClock(now);
        AuthorizationCodeService service = createService(clock);
        String code = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        now.set(NOW.plusSeconds(61));

        assertFalse(service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER).isPresent());
    }

    @Test
    void allowsOnlyOneConcurrentExchange() throws Exception {
        final AuthorizationCodeService service = createService(Clock.fixed(NOW, ZoneOffset.UTC));
        final String code = service.issue(CLIENT_ID, REDIRECT_URI, CHALLENGE);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<Boolean>> attempts = new ArrayList<Callable<Boolean>>();
            for (int i = 0; i < 32; i++) {
                attempts.add(new Callable<Boolean>() {
                    @Override
                    public Boolean call() {
                        return service.exchange(code, CLIENT_ID, REDIRECT_URI, VERIFIER).isPresent();
                    }
                });
            }

            int successes = 0;
            List<Future<Boolean>> results = executor.invokeAll(attempts);
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    successes++;
                }
            }
            assertEquals(1, successes);
        } finally {
            executor.shutdownNow();
        }
    }

    private static AuthorizationCodeService createService(Clock clock) {
        InMemoryOAuthClientRegistry clientRegistry = new InMemoryOAuthClientRegistry();
        clientRegistry.register(new OAuthClient(CLIENT_ID, Collections.singleton(REDIRECT_URI)));
        return new AuthorizationCodeService(
                new InMemoryAuthorizationCodeStore(),
                clientRegistry,
                new SecureRandom(),
                clock,
                Duration.ofSeconds(60));
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> instant;

        private MutableClock(AtomicReference<Instant> instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant.get();
        }
    }
}
