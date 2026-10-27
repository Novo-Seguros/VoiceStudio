# Nexus sign-in (Novo Seguros fork)

This fork can put the web UI behind **Nexus**, the Novo Seguros identity
broker. Each person signs in with their own Nexus account, and their Nexus role
decides what they can do in VoiceStudio. The production deployment is
`https://voicestudio.novoapp.dev`.

Nexus sign-in is **off unless `NEXUS_CLIENT_ID` is set**. Without it the
desktop app, Docker image and source build behave exactly like upstream.

## How it works

The backend is the OAuth client (PKCE). The browser never sees a Nexus token:

1. **Entrar com Nexus** opens `GET /auth/login`. The backend creates the PKCE
   pair and a single-use `state`, then redirects to
   `{NEXUS_SUPABASE_URL}/auth/v1/oauth/authorize`.
2. Nexus sends the browser back to `GET /auth/callback`. The backend exchanges
   the code and verifies the access token:
   - an `ES256` signature from `{NEXUS_API_URL}/v1/auth/jwks` (cached for 10
     minutes);
   - `iss`, an `aud` equal to `NEXUS_APP_URL`, and `system_slug`.
3. The token's permissions become VoiceStudio capabilities. The backend keeps
   the Nexus tokens in memory and sets the usual HttpOnly `ov_session` cookie.
4. Before an access token expires, the backend renews it on the next request
   and stores the rotated refresh token. Each renewal re-reads the
   permissions, so a role change in Nexus applies within about an hour. A
   session lasts at most 8 hours. Restarting the backend signs everyone out;
   the next sign-in is silent while the Nexus SSO session lives.

| Nexus permission | VoiceStudio capability | Reaches |
|---|---|---|
| `usar` | `consume` | generation, dubbing, transcription, voices |
| `admin` | `consume` + `admin` | the above plus Settings, engines, models, workers |
| neither | — | sign-in is refused (`sem_acesso`) |

Assign people in **Nexus Admin → Sistemas → voicestudio**. The system uses the
`GRANULAR` schema and allows one role per person. The roles are `usuario`
(`usar`) and Nexus's own `admin` role (`usar|admin`), which also manages
VoiceStudio users in Nexus.

## Configuration

| Variable | Value |
|---|---|
| `NEXUS_CLIENT_ID` | OAuth client ID from Nexus Admin (turns the mode on) |
| `NEXUS_SUPABASE_URL` | Nexus Supabase URL, e.g. `https://<ref>.supabase.co` |
| `NEXUS_SUPABASE_ANON_KEY` | Nexus Supabase anon key (sent as `apikey` to the token endpoint) |
| `NEXUS_API_URL` | `https://nexus.novoapp.dev`, without `/v1` |
| `NEXUS_APP_URL` | `https://voicestudio.novoapp.dev`, without a trailing slash; also the JWT `aud` |
| `NEXUS_SYSTEM_SLUG` | optional, defaults to `voicestudio` |
| `NEXUS_REDIRECT_URI` | optional; overrides `{NEXUS_APP_URL}/auth/callback`, for local testing only |

The callback URL is `{NEXUS_APP_URL}/auth/callback`, and it must be registered
as a redirect URI on the Nexus OAuth client. If `NEXUS_CLIENT_ID` is set but
any other value is missing or malformed, the mode stays on and fails closed:
sign-in answers `nexus_error=configuracao` and remote requests are still
refused.

The Nexus mode implies server mode (`OMNIVOICE_SERVER_MODE`), so admin routes
are reachable remotely by people with `admin`. `OMNIVOICE_API_KEY` keeps working
alongside Nexus as a break-glass credential for scripts and MCP clients. The
share PIN and `OMNIVOICE_TRUSTED_NETWORKS` still exempt their callers, so leave
them unset on a Nexus deployment.

## Local testing

Nexus sets the token `aud` to the system URL, so `NEXUS_APP_URL` stays the
production URL even on a developer machine. Register
`http://localhost:3901/auth/callback` as a redirect URI on the Nexus OAuth
client, then add one line to the root `.env`:

```
NEXUS_REDIRECT_URI=http://localhost:3901/auth/callback
```

Run `bun run dev:web` and open `http://localhost:3901`. When the root `.env`
has `NEXUS_CLIENT_ID`, the web dev server proxies `/auth/login` and
`/auth/callback` to the backend and sends `X-Forwarded-For`, so the backend
treats the browser as remote, the way it treats cloudflared traffic. Without
that header a loopback browser would skip sign-in.

## Behind a reverse proxy

Run the backend on loopback (`OMNIVOICE_BIND_HOST=127.0.0.1`, the default) and
publish it through a proxy on the same host, such as cloudflared or Caddy.
Uvicorn replaces the peer with the `X-Forwarded-For` address when the proxy is
in `FORWARDED_ALLOW_IPS` (default `127.0.0.1`). This keeps remote browsers from
being treated as local.

As a backstop in Nexus mode, a request that reaches the backend from loopback
but carries `CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP` or `Forwarded`
is never treated as local. `NEXUS_APP_URL`'s host name is accepted
automatically, so you don't need to list it in `OMNIVOICE_ALLOWED_HOSTS`.

## Clock-out reminder (lembrete do ponto)

Every system integrated with Nexus must show the clock-out reminder. After
sign-in, the UI loads `{NEXUS_API_URL}/v1/ponto/saida/lembrete.js` and starts
it in token-less mode (mode B):

- The script calls `POST /api/nexus-ponto/{situacao|registrar|dispensar}` on
  this origin, with the CSRF header.
- The backend forwards each call to `{NEXUS_API_URL}/v1/ponto/saida/<action>`
  with the session's Nexus token (renewed if needed). It passes the JSON body
  and the browser's `User-Agent` through unchanged, with a 10 s timeout.
- Any failure answers `502 {}`, which the script treats as "show nothing".

With the mode on, the backend adds the `NEXUS_API_URL` origin to `script-src`
in the served page's CSP. Sign-out stops the reminder before ending the
session.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /auth/login` | Starts sign-in (public) |
| `GET /auth/callback` | OAuth redirect URI (public) |
| `GET /api/auth/nexus/me` | `{email, name, admin, system, ponto_script}`; `401` without a session |
| `POST /api/auth/nexus/logout` | Ends the local session and revokes the refresh token at Nexus (best effort); needs the CSRF header |
| `POST /api/nexus-ponto/{action}` | Clock-out reminder relay |

All of them answer `404` while the mode is off.

## Troubleshooting

A failed sign-in returns to `/?nexus_error=<code>`, and the sign-in card
explains it:

| Code | Meaning | Fix |
|---|---|---|
| `estado_invalido` | state missing, reused, expired (10 min) or from another browser | sign in again |
| `cancelado` | the consent screen was declined | sign in again |
| `troca_falhou` | Nexus refused the code exchange (4xx) | check `NEXUS_CLIENT_ID` and the redirect URI |
| `nexus_indisponivel` | Nexus unreachable or 5xx | retry |
| `token_invalido` | signature, `iss`, `aud` or `system_slug` mismatch | `NEXUS_APP_URL` must equal the URL registered in Nexus; `NEXUS_SUPABASE_URL` must match the issuer |
| `sem_acesso` | the token has neither `usar` nor `admin` | give the person a VoiceStudio role in Nexus |
| `configuracao` | incomplete Nexus configuration on the server | set every variable above |

API responses use these details:

- `401 Nexus login required` means there is no valid session, and the UI shows
  the sign-in card.
- `403 Nexus admin permission required` means the person is signed in without
  the `admin` permission.
