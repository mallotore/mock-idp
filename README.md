# mock-idp

[![ci](https://github.com/mallotore/mock-idp/actions/workflows/ci.yml/badge.svg)](https://github.com/mallotore/mock-idp/actions/workflows/ci.yml)

A tiny OpenID Connect identity provider for **local development and CI**, for any OIDC application. Log in as any
email with any groups and claims, and get a signed ID token back. Only Docker is needed.

> Not secure by design, see [below](#not-secure-by-design). Never expose it outside a test environment.

- Log in as **any email, groups and extra claims**, or pick a saved user from `config/users.json`
- Skip the login form for scripts and CI: `POST /set-user` (next login only) or `MOCK_IDP_AUTO_LOGIN`
- RS256 ID tokens with discovery, JWKS, `/userinfo`, nonce and state
- Authorization-code flow with PKCE (`S256`, `plain`) and public clients
- Single-use, expiring authorization codes; client id/secret checked by Basic auth or form body
- Tested with an independent OIDC client (Authlib); [integration examples](#integration-examples) run against real applications

## Quickstart

```sh
docker run --rm -p 127.0.0.1:8081:8081 ghcr.io/mallotore/mock-idp    # http://127.0.0.1:8081
```

Or from a clone, which also mounts the sample users in `config/users.json`:

```sh
git clone https://github.com/mallotore/mock-idp.git && cd mock-idp
docker compose up --build
```

The image is built for `amd64` and `arm64` from every commit to `main` that passes CI (`:latest`, plus `:sha-<commit>`
to pin one).

Open `http://127.0.0.1:8081/authorize?redirect_uri=http://localhost/cb` to see the login page. Pick a saved
user (from `config/users.json`) or type any email, groups and extra claims.

Without Docker you need Python 3.11 or newer: `pip install .` and run `mock-idp` (or `python -m mock_idp`). It listens on
`127.0.0.1:8081` and keeps its signing keys in `./mock_idp_files`.

## Using it from your application

Configure your application as an OIDC client:

| Setting | Value |
|---|---|
| Issuer / discovery URL | `http://127.0.0.1:8081` (discovery is at `/.well-known/openid-configuration`) |
| Client id / secret | `mock-idp-client` / `mock-idp-secret` (change them with `MOCK_IDP_CLIENT_ID` and `MOCK_IDP_CLIENT_SECRET`) |
| Scopes | `openid` (plus anything else, see [Not supported](#not-supported)) |
| Redirect URI | anything; it is not checked |

The issuer must equal the discovery URL your client is configured with, because it is the token's `iss`.

### My application also runs in a container

Two URLs are involved: containers reach the IdP by its service name, your browser reaches it on localhost.

```yaml
services:
  mock-idp:
    image: ghcr.io/mallotore/mock-idp:latest
    environment:
      MOCK_IDP_ISSUER: http://mock-idp:8081             # what your app container uses as issuer / discovery URL
      MOCK_IDP_PUBLIC_URL: http://127.0.0.1:8081        # what your browser uses for /authorize
    ports: ["127.0.0.1:8081:8081"]
```

### Keeping the signing key across restarts

A new container makes a new signing key. The key ID changes with it, so applications fetch the new key, but tokens
issued before the restart stop validating. To keep the key, put `/data/keys` on a named volume:

```yaml
services:
  mock-idp:
    image: ghcr.io/mallotore/mock-idp:latest
    volumes: ["mock-idp-keys:/data/keys"]
volumes:
  mock-idp-keys:
```

or `docker run -v mock-idp-keys:/data/keys ...`.

## Skipping the login form (scripts and CI)

- `POST /set-user` (`Content-Type: application/json`) with
  `{"email": "bot@example.com", "groups": ["ci"], "claims": {"name": "Bot"}}`: the **next** login uses that
  identity, once.
- or set `MOCK_IDP_AUTO_LOGIN=admin@example.com` (under `environment` in `docker-compose.yml`): every login is that user.
  `/set-user` wins over it for the next login.

## Configuration

Environment variables, set in `docker-compose.yml`. An empty value counts as unset and gets the default:

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
| `MOCK_IDP_KEY_DIR` | `./mock_idp_files` (the image uses `/data/keys`) | Keys are regenerated whenever the container is recreated unless the directory is on a volume, see [Keeping the signing key across restarts](#keeping-the-signing-key-across-restarts) |

`config/users.json` is re-read on every login, so you can edit it without restarting. Every key other than
`email` and `groups` becomes a claim:

```json
{"users": [{"email": "admin@example.com", "groups": ["admins@example.com"], "name": "Ada Admin", "email_verified": true}]}
```

Many applications refuse a login without `"email_verified": true`, and some show `name`. The sample users have both;
when you type an identity in the login form or send one to `/set-user`, add them as extra claims if your
application needs them.

Invalid settings stop the server at start-up with a message that names the setting. If `users.json` is broken while
the server is running, `/authorize` answers `500` with `invalid_users_file` and the reason; fix the file and retry.

### Claims recipes

Every identity has `sub` (the email unless overridden), `email` and `groups`. Anything else is an extra claim: a
key in `users.json`, the `claims` object of `/set-user`, or the JSON in the login form's extra claims field. Extra
claims can be any JSON value, nested objects included.

| Your application expects | Give the identity |
|---|---|
| Groups in `groups` | The groups field: comma-separated in the form, a list in `users.json` and `/set-user` |
| Roles in a claim of their own | `{"roles": ["admin"]}`, under whatever name the application reads |
| A username | `{"preferred_username": "ada"}` |
| An id rather than the email as `sub` | `{"sub": "user-123"}` |
| Keycloak-style nested roles | `{"realm_access": {"roles": ["admin"]}}` |
| A verified email | `{"email_verified": true}` |

On the application side, point it at those claims. For example:

- Vault (OIDC auth role): `user_claim=email groups_claim=groups`, as in the [Vault example](examples/vault/README.md).
- Grafana (`[auth.generic_oauth]`): `groups_attribute_path = groups` and
  `role_attribute_path = contains(groups[*], 'admins@example.com') && 'Admin' || 'Viewer'`.

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
Codes expire after 60 s and are single use. Token responses are sent with `Cache-Control: no-store`.

## Not secure by design

- No passwords and no consent: anyone who can reach the server can log in as any identity.
- A single static client; any `redirect_uri` is accepted.
- `POST /login` does not re-validate what `/authorize` checked (`client_id`, `response_type`, `scope`). Posting
  to it directly issues a code without those checks, so the checks in `/authorize` are not a security boundary.
- `POST /set-user` is unauthenticated (it only requires a JSON content type, which keeps cross-site form posts out).

## Not supported

- **Scopes do not filter claims**: `/userinfo` returns every claim whatever scopes were requested.
- Only the authorization-code grant: no refresh tokens, implicit, password or client-credentials grants.
- No logout (`end_session`) endpoint, no consent screen, no dynamic client registration.
- No login session: every `/authorize` shows the form again (unless `/set-user` or auto-login applies), and
  `prompt=none` is ignored.
- A single static client; `redirect_uri` is optional on `/token` and is not checked against a registered list.
- `/login` does not re-validate the authorize parameters (see above).
- Signing keys are regenerated when the container is recreated, unless `/data/keys` is on a volume.

## Integration examples

- [Vault](examples/vault/README.md): OIDC auth method with group-to-policy mapping, checked against a real Vault
  by `./examples/vault/run.sh`.

## Development

Everything runs from the repo root and needs only Docker.

| I want to... | Command |
|---|---|
| Start the IdP | `docker compose up --build` |
| Stop it | `docker compose down` |
| Run all tests | `docker compose run --rm --build test` |
| Run the fast tests only | `docker compose run --rm --build test pytest -m "not e2e" -q` |
| Run one test file | `docker compose run --rm --build test pytest tests/e2e/test_flow.py -q` |
| Run tests matching a name | `docker compose run --rm --build test pytest -k pkce -q` |
| Lint and check formatting (ruff) | `docker compose run --rm --build lint` |
| Type-check (mypy) | `docker compose run --rm --build lint mypy` |
| Check the real image works | `./scripts/smoke.sh` (builds it, starts it, curls the endpoints) |
| Check against a real Vault | `./examples/vault/run.sh` (CI runs it every Monday, or by hand) |
| Add or change users | edit `config/users.json` (re-read on every login, no restart) |

Layout:

```
src/mock_idp/     the package: app, routes, settings, users, pkce, stores, tokens, keys, errors, parsing, templates/
tests/unit/       pure functions and small classes, no HTTP
tests/api/        endpoint behaviour through the Flask test client, one file per topic
tests/e2e/        the full login over real HTTP, Authlib as an independent client, real start-up
examples/vault/   a real-Vault check (run.sh, check.py, compose overlay)
config/users.json sample users mounted by the compose file
```

### Extending

The project stays small on purpose: it covers what an application needs to log in during local development and CI,
not every OIDC feature. If you need refresh tokens, sessions or several clients, a full IdP such as
[Dex](https://dexidp.io) fits better. If you need one more thing, these are the places to touch:

- **An endpoint**: add a route to `oidc_bp` in `src/mock_idp/routes.py`. `app_state()` gives the settings and the
  stores; raise `OAuthError(INVALID_REQUEST, "why")` for a client error and it becomes a JSON error response.
- **A claim in every token**: `identity_claims` in `src/mock_idp/users.py` builds both the ID token claims and the
  `/userinfo` response. `RESERVED_CLAIMS` lists the claims extra claims cannot override.
- **A setting**: add a field with its default to `Settings` in `src/mock_idp/settings.py`, read it in `from_env`,
  and add a row to the configuration table above.
- **Tests**: `tests/api/test_<topic>.py` with the `client` fixture for endpoint behaviour; `make_app(**overrides)`
  builds an app with other settings, `clock` controls time, and `live_server` serves over real HTTP for `tests/e2e/`.

Tests are marked `unit`, `api` or `e2e` by directory, so `pytest -m "not e2e"` is the fast run. Dependencies are
pinned in `pyproject.toml`; the `test` and `dev` extras add the test and lint tools.

## License

MIT, see [LICENSE](LICENSE).
