<div align="center">

![AnAuthentia — Trust nobody. Verify everything.](assets/anauthentia-banner.png)

# AnAuthentia

**Trust nobody. Verify everything.**

*An OAuth 2.0 library for Java applications. No embedded server, no framework lock-in.*

</div>

> **Status: early development.** The core authorization-code and token lifecycle APIs are implemented and tested. No production-ready release or Maven Central artifact is published yet.

## Why AnAuthentia?

AskAI and Pyloros currently maintain separate OAuth implementations with overlapping responsibilities. **AnAuthentia** extracts common, security-sensitive logic into one tested library, so both applications can share it without coupling their HTTP stacks.

The name is an intentionally mischievous play on *authentia* and anarchy. The logo is rebellious; the security model is not.

## Design goals

- **Library first:** no standalone HTTP server or centrally hosted identity provider.
- **Framework-independent core:** no runtime dependency on Vert.x, Spring, Swing, or a specific Java HTTP server.
- **Java 8 baseline:** usable from AskAI while remaining compatible with Pyloros on Java 21.
- **OAuth 2.0 authorization flows:** authorization codes, PKCE S256, client-secret validation, bearer access tokens, refresh tokens, and optional refresh-token rotation.
- **Security by default:** PKCE S256, exact redirect URI allow-lists, one-time authorization-code consumption, bounded token lifetimes, serialized token state transitions, and no credentials or tokens in logs. Hosts may explicitly inject redirect policies or enable missing/legacy plain-PKCE compatibility when an existing protocol integration requires it.
- **Replaceable persistence and time:** interfaces for refresh-token persistence and injectable clocks for deterministic tests.
- **Thorough tests:** concurrent code exchange, replay, expiry, rotation, invalid credentials, and refresh-token restoration through a host-provided store.

## Planned integration

| Application | HTTP adapter | Java |
| --- | --- | --- |
| [AskAI](https://github.com/Miguel0888/askai-java8) | Existing Java HTTP server | 8+ |
| [Pyloros](https://github.com/aresstack/pyloros) | Vert.x routes | 21 |

Application-specific endpoints, OAuth discovery metadata, HTTP request/response handling, and durable storage adapters remain in those projects. AnAuthentia provides reusable OAuth logic through Java APIs.

## Current implementation

The current branch contains:

- PKCE S256 verification using an RFC 7636 test vector.
- Framework-neutral authorization-code issuance and exchange, with exact redirect URI matching, client binding, scope retention, expiry, and atomic one-time consumption.
- Client registration with exact redirect URI allow-lists and constant-time comparison for confidential-client secrets.
- Access-token issuance and Bearer-token validation with configurable expiry.
- Refresh-token lifecycle with configurable expiry, optional rotation, and a short replay window to tolerate identical parallel token requests.
- A `RefreshTokenStore` abstraction with synchronized in-memory and file-backed implementations.
- Versioned refresh-token snapshots written to a temporary file and replaced atomically when the filesystem supports it; POSIX file permissions are restricted to the owner where available.
- Persistence-first token rotation so a failed save does not invalidate the previous refresh token, plus tests for cross-client token misuse and storage failures.
- Tests for successful exchange, invalid client credentials, expiry, invalid PKCE, replay, rotation, concurrent code exchange, file-store round trips, corrupt-store rejection, and restoring refresh-token state after service reconstruction.

## Important limitations

AnAuthentia is an embeddable library, **not a standalone OAuth server**. The host application owns HTTP endpoints, protocol serialization, client configuration, OAuth discovery, and durable storage.

The in-memory authorization-code and client-registry implementations do not survive restarts or coordinate multiple instances. `FileRefreshTokenStore` preserves refresh-token state across restarts, but stores bearer-equivalent credentials without encryption and does not coordinate multiple processes writing the same path. Protect the file and parent directory. Access tokens and short replay caches are intentionally process-local, so restarting an application invalidates its access tokens.

The library does not yet include complete AskAI/Pyloros integration adapters, and no Maven Central artifact has been published. Review host integration, deployment permissions, and multi-instance requirements before production use.

**Do not use this library in production yet.** Before release, complete host integration tests, review persistence failure semantics and multi-instance behavior, and verify compatibility with the actual ChatGPT connector flows.

## Using AnAuthentia

After the first release is published, add the dependency:

```gradle
dependencies {
    implementation 'com.aresstack:anauthentia:0.1.0'
}
```

The library does not start an HTTP server. Compose its services in the host application and connect them to the host's existing authorization and token routes.

```java
Set<String> redirectUris = new HashSet<String>();
redirectUris.add("https://chatgpt.com/connector/oauth/example");

OAuthClient client = new OAuthClient("chatgpt", clientSecret, redirectUris);
InMemoryOAuthClientRegistry clients = new InMemoryOAuthClientRegistry();
clients.register(client);

Clock clock = Clock.systemUTC();
SecureRandom secureRandom = new SecureRandom();

AuthorizationCodeService authorizationCodes = new AuthorizationCodeService(
        new InMemoryAuthorizationCodeStore(),
        clients,
        secureRandom,
        clock,
        Duration.ofMinutes(5));

OAuthTokenService tokens = new OAuthTokenService(
        authorizationCodes,
        clients,
        new FileRefreshTokenStore(Paths.get("data/refresh-tokens.db")),
        secureRandom,
        clock,
        Duration.ofMinutes(15),
        Duration.ofDays(30),
        true);
```

The host authorization route validates the incoming request and redirects to the returned URI:

```java
String redirectUri = authorizationCodes.authorize(
        responseType,
        clientId,
        requestedRedirectUri,
        state,
        requestedScope,
        codeChallenge,
        codeChallengeMethod);
```

The host token route passes validated request parameters to the library:

```java
TokenResponse response = tokens.exchangeToken(
        clientId,
        clientSecret,
        grantType,
        code,
        refreshToken,
        redirectUri,
        codeVerifier);
```

The host serializes `TokenResponse` using its existing JSON/HTTP stack. Validate incoming bearer credentials with `tokens.checkBearerAuth(authorizationHeader)`. Map `OAuthException` to the host's OAuth error response without exposing internal exception details.

The example uses in-memory client and authorization-code stores. Replace them with host-appropriate implementations if the application runs across multiple processes or requires state to survive restarts. Keep client secrets in the host's secret configuration; never hard-code real credentials in source control.

## Security

This is security-sensitive code. Changes to OAuth flows, PKCE, client authentication, token storage, or redirect handling require tests and review. Never post real client secrets, authorization codes, or bearer/refresh tokens in public issues or logs.

---

<div align="center">

*Open source. Zero trust. A little anarchy in the artwork — none in the authorization rules.*

</div>
