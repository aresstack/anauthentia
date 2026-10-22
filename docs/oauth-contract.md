# OAuth-Vertrag der AresStack-Plattform (AP 1)

Stand: 2026-10-22 · Grundlage: Code-Analyse von `askai-java8`, `pyloros`,
`anauthentia` und `webserver` (Branch `feature/managed-jar-applications`).

Dieses Dokument ist das Abnahmeergebnis von **AP 1 — Bestandsaufnahme und
OAuth-Vertrag**. Es beschreibt (1) den heutigen IST-Vertrag beider
Implementierungen, (2) den verbindlichen ZIEL-Vertrag (Variante B: zentrale
Token-Ausstellung, verteilte lokale JWT-Validierung) und (3) die
Kompatibilitäts- und Härtungsanforderungen für die Migration.

---

## 1. IST-Zustand

AskAI (`research-agent-ui-plugin/.../connector/`) und Pyloros
(`pyloros-auth-oauth`) implementieren denselben, aus ChatGPT-MCP-Anbindung
gewachsenen Vertrag unabhängig voneinander. Die Gemeinsamkeiten bilden den
faktischen Bestandsvertrag:

### 1.1 Endpunkte (beide Implementierungen identisch im Verhalten)

| Endpunkt | Methode | Verhalten |
| --- | --- | --- |
| `/.well-known/oauth-authorization-server` (+ `/openid-configuration`) | GET | AS-Metadaten: `response_types=[code]`, `grant_types=[authorization_code, refresh_token]`, `token_endpoint_auth_methods=[client_secret_basic, client_secret_post]`, `code_challenge_methods=[S256]`, `scopes=[mcp]`. Kein `registration_endpoint`, kein `jwks_uri`, kein `revocation_endpoint`. |
| `/.well-known/oauth-protected-resource` | GET | `{resource: <origin>/, authorization_servers: [<origin>], scopes_supported: [mcp], bearer_methods_supported: [header]}` |
| `/oauth/authorize` | GET | Prüft `response_type=code`, statisches `client_id`, redirect-Host-Whitelist (`chatgpt.com`, `chat.openai.com`, nur https). **Kein Login/Consent** — sofortige 302-Antwort mit `?code=…&state=…`, `Cache-Control: no-store`. |
| `/oauth/token` | POST | Form-encoded. Grants: `authorization_code` (mit `code`, optional `redirect_uri`, `code_verifier`) und `refresh_token`. Client-Auth per Basic oder Form. Antwort: `{access_token, token_type: "Bearer", expires_in: 3600, refresh_token, scope: "mcp"}` mit `no-store`/`no-cache`. |
| `/health` bzw. `/actuator/health` | GET | Öffentlich, ohne Auth. |
| `/` (MCP JSON-RPC + SSE) | GET/POST | Bearer-geschützt; 401 mit `WWW-Authenticate: Bearer error="invalid_token", error_description="The access token is invalid or expired"`. |

Fehlerformat: RFC-6749-JSON (`{"error": "...", "error_description": "..."}`),
401 für `invalid_client` am Token-Endpoint, sonst 400.

### 1.2 Token-Modell heute

- **Opake Tokens**, prozesslokal: AskAI 32 Byte SecureRandom → base64url
  (43 Zeichen); Pyloros 2×UUID → 64 Hex-Zeichen.
- TTLs: Auth-Code **300 s**, Access-Token **3600 s**, Refresh-Token
  **30 Tage**, Replay-Fenster **10 s**.
- **Replay-Cache** (beide): derselbe Auth-Code darf innerhalb 10 s mit
  identischen Parametern erneut getauscht werden und liefert die identische
  Antwort — ChatGPT sendet parallele Doppel-Exchanges. Dieses Verhalten ist
  Teil des Vertrags und muss erhalten bleiben.
- Persistenz: nur Refresh-Tokens, Klartext-JSON mit atomarem
  `.tmp`+rename (AskAI `~/.askai-java8/chatgpt-connector/oauth-refresh-tokens.json`,
  Pyloros `data/oauth-refresh-tokens.json`). Access-Tokens überleben keinen
  Neustart; Clients refreshen.
- Rotation: AskAI nie; Pyloros optional (Default aus), mit 10-s-Replay-Cache
  für den alten Refresh-Token.
- Kein Revocation-, Introspection- oder Registration-Endpoint.

### 1.3 Client-Modell heute

- Genau **ein statischer Client** pro Dienst (`client_id`/`client_secret` aus
  Konfiguration). Keine dynamische Registrierung (RFC 7591).
- PKCE **optional** („Kompatibilitätsmodus": ohne `code_challenge` keine
  Prüfung); AskAI fällt bei unbekannter Methode sogar auf `plain` zurück,
  obwohl die Metadaten nur S256 bewerben.
- `redirect_uri` wird am Token-Endpoint nur geprüft, wenn mitgesendet
  (RFC-6749-Verstoß).
- Scope `mcp` wird durchgereicht, aber **nirgends geprüft**.

### 1.4 Dokumentierte Schwächen (müssen die Migration überleben ≠ dürfen)

Bewusst zu erhalten (Vertragsbestandteil):
- Code-/Refresh-Replay-Fenster (10 s, identische Antwort).
- Discovery-Pfade und Antwortfelder wie oben.
- 302-Sofort-Code ohne Consent (bis ein Login-Feature existiert — separates
  Vorhaben, nicht Teil dieser Migration).

Zu beheben (Härtungsliste für AP 2/3):
1. Unsynchronisierte `LinkedHashMap`-Token-Stores (Pyloros) bzw. globaler
   Lock inkl. Datei-I/O (AskAI).
2. Vollständige Authorization-Codes in INFO-Logs (Pyloros
   `OAuthService.java:65-66,107-108`).
3. PKCE-Downgrade (optional/plain) — Ziel: S256 verpflichtend, sobald der
   Client eine Challenge sendet; „ohne Challenge" nur als konfigurierbarer
   Kompatibilitätsmodus.
4. Kein constant-time-Vergleich für Client-Secrets und Tokens.
5. Default-/Leer-Credentials werden akzeptiert (AskAI `change-me`, Pyloros
   `""`).
6. Pyloros „fixed access token"-Hintertür (`OAUTH_ACCESS_TOKEN`).
7. Refresh-Tokens im Klartext auf Platte → mindestens Hashing, unter Windows
   DPAPI (Webserver bringt `WindowsDpapiSecrets` bereits mit).
8. `redirect_uri`-Pflichtprüfung gemäß RFC 6749.
9. Unbegrenzt wachsende Access-Token-Maps (Cleanup nur lazy).
10. `WWW-Authenticate` bei *fehlendem* Token ohne `error`-Parameter
    (RFC 6750) und mit `resource_metadata`-Hinweis (RFC 9728).

---

## 2. ZIEL-Vertrag (Variante B)

### 2.1 Rollen

- **AresStack Webserver** = Authorization Server (Issuer). Betreibt die
  OAuth-Runtime als Loopback-HTTP-Dienst im eigenen Java-21-Prozess; Caddy
  routet die öffentlichen Pfade dorthin.
- **AskAI / Pyloros** = Resource Server. Validieren Access-Tokens **lokal**
  über die AnAuthentia-Validierungs-API (kein Netzaufruf pro Request).
- **AnAuthentia** = gemeinsame Bibliothek (Java 8, zero runtime deps) für
  Ausstellung UND Validierung. Flows/PKCE/Stores existieren bereits
  (`oauth`-Package, 21 Klassen, 8 Testklassen); JWT/JWKS sind AP 3.

### 2.2 Access-Token: JWT nach RFC 9068

| Eigenschaft | Festlegung |
| --- | --- |
| Format | JWS, `typ: "at+jwt"`, Signatur **RS256** (Allowlist: nur RS256; `none`/HS* hart abgelehnt) |
| `iss` | Öffentliche Basis-URL des Webservers (konfigurierbar; pro Installation genau ein Issuer) |
| `aud` | Ressourcen-URL des Zieldienstes (die veröffentlichte Site-URL, z. B. `https://askai.example.com/`) |
| `sub` | `client_id` (bis es Benutzer-Logins gibt) |
| `scope` | Space-separierte Scopes; Default weiterhin `mcp` |
| `exp` / `iat` / `jti` | Pflicht; Laufzeit **600 s** (konfigurierbar 300–900 s) |
| `kid` | Pflicht im Header; verweist auf JWKS |

Validierung im Resource Server (verpflichtend, Reihenfolge egal, alle hart):
Signatur gegen JWKS-Key mit passendem `kid` → `alg`-Allowlist → `typ` →
`iss` → `aud` (muss die eigene Ressource sein) → `exp`/`iat` mit max. 60 s
Clock-Skew → Scope-Prüfung pro Operation.

### 2.3 Refresh-Tokens

Bleiben **opak** (32 Byte SecureRandom, base64url), zentral im Webserver
gespeichert (nur Hash auf Platte, DPAPI-geschützt), Laufzeit 30 Tage,
Rotation **an** mit 10-s-Replay-Cache (Bestandsverhalten). Widerruf über
neuen `POST /oauth/revoke` (RFC 7009).

### 2.4 Schlüssel und JWKS

- RSA 2048+, privater Schlüssel nur im Webserver (DPAPI-geschützt unter
  `data/oauth/keys/`), niemals in webserver.json.
- `GET /.well-known/jwks.json` (und `jwks_uri` in den AS-Metadaten) liefert
  alle aktuell gültigen öffentlichen Schlüssel.
- Rotation: neuer Schlüssel wird ausgestellt, alter bleibt bis
  `max(access_ttl)+Skew` im JWKS; Resource Server cachen JWKS mit TTL
  (z. B. 5 min) und erzwingen Refresh bei unbekanntem `kid` (mit
  Backoff gegen Key-Spray).

### 2.5 Endpunkte des zentralen AS (Webserver)

Unverändert gegenüber IST (Pfad-kompatibel für bestehende Clients):
`/.well-known/oauth-authorization-server`, `/oauth/authorize`,
`/oauth/token`. Neu: `jwks_uri`, `/oauth/revoke`,
`revocation_endpoint`-Metadatum. Die
`/.well-known/oauth-protected-resource`-Metadaten liefert **weiterhin der
jeweilige Dienst-Host** (per Caddy auf den zentralen AS geroutet, aber mit
der Ressourcen-URL des Dienstes gemäß RFC 9728 — inklusive Pfad, falls die
Site unter einem Pfad veröffentlicht ist).

Kompatibilitätsregel: Bestehende öffentliche URLs der Dienste bleiben
gültig; Caddy routet `/.well-known/*` und `/oauth/*` jeder geschützten Site
auf die zentrale Runtime. `issuer` wechselt damit pro Site auf die
Site-Origin ODER zentral auf einen gemeinsamen Issuer — Entscheidung:
**pro-Site-Issuer in Phase 1** (keine Client-Neuautorisierung nötig),
gemeinsamer Issuer (`auth.<domain>`) optional später.

### 2.6 Client-Modell Ziel

- Client-Registry im Webserver (persistiert in webserver.json unter einem
  neuen Top-Level-Feld, Secrets DPAPI-geschützt wie Managed-App-Secrets).
- Weiterhin statische Clients; Registrierungs-Endpoint (RFC 7591) bewusst
  **außerhalb** des ersten Umfangs.
- PKCE: S256 verpflichtend, sobald eine Challenge gesendet wird; `plain`
  entfällt. Redirect-Whitelist konfigurierbar pro Client (Default wie heute
  `chatgpt.com`/`chat.openai.com`; vorbereitet für Claude-Hosts).
- Secret-Vergleich constant-time (`MessageDigest.isEqual`).

### 2.7 Webserver-Integration (Andockpunkte, aus Code-Analyse)

- Konfiguration: neues `FileModel`-Feld `oauth` (Issuer-Modus, Key-Pfad,
  Clients) analog `AcmeModel`; pro Site ein optionales `authentication`-Feld
  im `SiteModel` (`none` | `central-oauth`, `resource`, `requiredScopes`) —
  gleiches Optional-Muster wie `managedApplication`.
- Lifecycle: OAuth-Runtime startet/stoppt neben `managedProcesses` in
  `WebServerController.start()/stop()/restart()` und im Headless-Pfad von
  `WebServerMain.runHeadless()`.
- Caddy: `CaddyfileRenderer.renderSite()` ergänzt für geschützte Sites die
  Routen auf die Loopback-Runtime (`/oauth/*`, `/.well-known/*`);
  `forward_auth` bleibt **optional** (Defense-in-Depth), da die Backends
  selbst validieren.

---

## 3. Abnahme-Szenarien (Vertragstests)

Diese Fälle fixieren den Vertrag und müssen in AP 2/3 als Tests existieren:

1. Discovery AS + Protected-Resource liefern die Felder aus 2.5 inklusive
   `jwks_uri` und korrekter Ressourcen-URL mit Pfad.
2. Authorization-Code-Flow mit S256-PKCE: Code einmalig, 300 s TTL,
   Doppel-Exchange innerhalb 10 s liefert identische Antwort, danach
   `invalid_grant`.
3. `redirect_uri`-Mismatch und nicht-gelistete Hosts → `invalid_request`;
   Pflichtprüfung auch, wenn der Client sie beim Exchange weglässt, sie beim
   Authorize aber gesendet hat.
4. Access-Token: Resource Server akzeptiert gültiges JWT offline; lehnt ab:
   falsche Signatur, `alg=none`/HS256, falsche `aud`, falscher `iss`,
   abgelaufen (> Skew), fehlender Scope → 401/403 mit korrektem
   `WWW-Authenticate` inkl. `resource_metadata`.
5. Refresh: Rotation mit Replay-Fenster; widerrufener Refresh-Token →
   `invalid_grant`; Neustart des Webservers invalidiert keine gültigen
   Access-Tokens und keine persistierten Refresh-Tokens.
6. Schlüsselrotation: Tokens mit altem `kid` bleiben bis Ablauf gültig;
   unbekannter `kid` löst JWKS-Refresh aus.
7. Ungeschützte Sites bleiben byte-identisch zum heutigen Caddy-Rendering.

---

## 4. Konsequenzen für die Arbeitspakete

- **AP 2 (Core)**: Härtungsliste 1.4 in den bestehenden
  AnAuthentia-Services umsetzen (constant-time, PKCE-Pflicht-S256,
  redirect-Pflichtprüfung, kein Credential-Default, Log-Hygiene).
- **AP 3 (JWT/JWKS)**: RFC-9068-Issuer + Validator in AnAuthentia; JWT-Teil
  ohne externe Runtime-Dependency ist mit JCA (RSA/SHA-256, Base64url)
  machbar — Entscheidung über eine Minimal-JOSE-Eigenimplementierung vs.
  optionale Dependency fällt zu Beginn von AP 3 (Java-8-Zwang schließt
  die meisten aktuellen JOSE-Libs nicht aus: nimbus-jose-jwt 9.x ist
  Java-8-kompatibel und wäre die bevorzugte Wahl).
- **AP 4/5 (Webserver)**: Andockpunkte aus 2.7.
- **AP 6/7 (Migration)**: AskAI zuerst (einfacherer HTTP-Stack); Pyloros
  danach; „fixed token"-Hintertür und `security.mode=none` werden durch die
  pro-Site-`authentication: none`-Option ersetzt.
