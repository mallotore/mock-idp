# mock-idp

[![ci](https://github.com/mallotore/mock-idp/actions/workflows/ci.yml/badge.svg)](https://github.com/mallotore/mock-idp/actions/workflows/ci.yml)

A tiny OpenID Connect identity provider for **local development and CI**, for any OIDC application. Log in as any
email with any groups and claims, and get a signed ID token back. Only Docker is needed.

> Not secure by design, see [below](#not-secure-by-design). Never expose it outside a test environment.

## Features at a glance

- Log in as **any email, groups and extra claims**, or pick a saved user from `config/users.json`
- Skip the login form for scripts and CI: `POST /set-user` (next login only) or `MOCK_IDP_AUTO_LOGIN`
- RS256 ID tokens with discovery, JWKS, `/userinfo`, nonce and state
- PKCE (`S256`, `plain`) and public clients
- Single-use, expiring authorization codes; client id/secret checked by Basic auth or form body
- Runs with **Docker only**: no Python or pip to install
- Tested with an independent OIDC client (Authlib); [integration examples](#integration-examples) run against real applications
- Invalid settings stop the server at start-up with a message naming the setting

## Quickstart

```sh
git clone <repo> && cd mock-idp
docker compose up --build        # http://127.0.0.1:8081
```

Open `http://127.0.0.1:8081/authorize?redirect_uri=http://localhost/cb` to see the login page. Pick a saved
user (from `config/users.json`) or type any email, groups and extra claims.

Point your application at `http://127.0.0.1:8081` as the OIDC issuer, with client id `mock-idp-client`
and secret `mock-idp-secret` (both configurable).

### Skipping the login form (scripts and CI)
- `POST /set-user` (`Content-Type: application/json`) with
  `{"email": "bot@example.com", "groups": ["ci"], "claims": {"name": "Bot"}}`: the **next** login uses that
  identity, once.
- or set `MOCK_IDP_AUTO_LOGIN=admin@example.com` (see `docker-compose.yml`): every login is that user.

### My application also runs in a container
Two URLs are involved: containers reach the IdP by its service name, your browser reaches it on localhost.

```yaml
services:
  mock-idp:
    build: ./mock-idp
    environment:
      MOCK_IDP_ISSUER: http://mock-idp:8081             # what your app container uses as issuer / discovery URL
      MOCK_IDP_PUBLIC_URL: http://127.0.0.1:8081        # what your browser uses for /authorize
    ports: ["127.0.0.1:8081:8081"]
```

The issuer must equal the discovery URL your client is configured with, because it is the token's `iss`.

## Cheat sheet

Everything runs from the repo root and needs only Docker.

| I want to... | Command |
|---|---|
| Start the IdP | `docker compose up --build` |
| Stop it | `docker compose down` |
| Run all tests | `docker compose run --rm --build test` |
| Run the fast tests only | `docker compose run --rm --build test pytest -m "not e2e" -q` |
| Run one test file | `docker compose run --rm --build test pytest tests/e2e/test_flow.py -q` |
| Run tests matching a name | `docker compose run --rm --build test pytest -k pkce -q` |
| Check the real image works | `./scripts/smoke.sh` (builds it, starts it, curls the endpoints) |
| Check against a real Vault | `./examples/vault/run.sh` (optional, manual in CI) |
| Add or change users | edit `config/users.json` (re-read on every login, no restart) |
| Log in without the form | uncomment `MOCK_IDP_AUTO_LOGIN` in `docker-compose.yml`, or `POST /set-user` |

What the tests cover:

- `tests/unit/`: pure functions and small classes (PKCE, users, errors, request parsing, keys, settings), no HTTP.
- `tests/api/`: endpoint behaviour and error cases through the Flask test client, one file per topic.
- `tests/e2e/test_flow.py`: the full login over real HTTP, verifying tokens through discovery and JWKS.
- `tests/e2e/test_rp_conformance.py`: Authlib as an independent relying party, including state, nonce, audience, expiry and PKCE checks.

Tests are marked `unit`, `api` or `e2e` by directory, so `pytest -m "not e2e"` is the fast run.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /authorize` | Login form (or instant redirect for `/set-user` / auto-login). Supports PKCE (`S256`, `plain`) |
| `POST /login` | Form target; issues a single-use code |
| `POST /token` | Authorization-code grant. Client auth by HTTP Basic or form body; public clients allowed with PKCE |
| `GET /userinfo` | Claims for a Bearer access token |
| `GET /jwks` | Public signing key (RSA key generated on first start) |
| `POST /set-user` | Identity for the next login |
| `GET /healthz` | Liveness |

ID tokens are RS256 and contain `sub` (the email unless overridden), `email`, `groups`, any extra claims,
and `nonce` when sent. `iss`, `aud`, `exp`, `iat` and `nonce` cannot be overridden by extra claims.
Codes expire after 60 s and are single use.

## Configuration

Environment variables, set in `docker-compose.yml`:

| Variable | Default | Notes |
|---|---|---|
| `MOCK_IDP_ISSUER` | `http://127.0.0.1:8081` | `iss` claim and base of token/userinfo/jwks URLs |
| `MOCK_IDP_PUBLIC_URL` | same as issuer | Base URL of `/authorize` as seen by the browser |
| `MOCK_IDP_CLIENT_ID` / `MOCK_IDP_CLIENT_SECRET` | `mock-idp-client` / `mock-idp-secret` | |
| `MOCK_IDP_USERS_FILE` | unset (compose mounts `config/users.json`) | Predefined users, see below |
| `MOCK_IDP_AUTO_LOGIN` | unset | Email to log in automatically |
| `MOCK_IDP_CODE_TTL` / `MOCK_IDP_TOKEN_TTL` | `60` / `3600` | seconds |
| `MOCK_IDP_PORT` / `MOCK_IDP_HOST` | `8081` / `127.0.0.1` (`0.0.0.0` in the image) | The compose file publishes on `127.0.0.1` only. If you change the port, change `ports` in `docker-compose.yml` too |
| `MOCK_IDP_DEBUG` | `false` | Flask debug mode; refused unless `MOCK_IDP_HOST` is loopback |
| `MOCK_IDP_KEY_DIR` | `./mock_idp_files` (the image uses `/data/keys`) | Keys are regenerated whenever the container is recreated |

`config/users.json` is re-read on every login, so you can edit it without restarting. Every key other than
`email` and `groups` becomes a claim:

```json
{"users": [{"email": "admin@example.com", "groups": ["admins@example.com"], "name": "Ada Admin"}]}
```

Invalid settings stop the server at start-up with a message that names the setting. If `users.json` is broken while
the server is running, `/authorize` answers `500` with `invalid_users_file` and the reason; fix the file and retry.

## Not secure by design

- No passwords and no consent: anyone who can reach the server can log in as any identity.
- A single static client; any `redirect_uri` is accepted.
- `POST /login` does not re-validate what `/authorize` checked (`client_id`, `response_type`, `scope`). Posting
  to it directly issues a code without those checks, so the checks in `/authorize` are not a security boundary.
- `POST /set-user` is unauthenticated (it only requires a JSON content type, which keeps cross-site form posts out).

## Integration examples

- [Vault](examples/vault/README.md): OIDC auth method with group-to-policy mapping, checked against a real Vault
  by `./examples/vault/run.sh`.

## License

MIT, see [LICENSE](LICENSE).
