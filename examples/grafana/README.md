# Grafana example

Logs in through a real Grafana with the mock IdP as its generic OAuth provider and checks that the `groups` claim
maps to Grafana roles. Needs only Docker:

```sh
./examples/grafana/run.sh
```

Grafana is configured with environment variables only (see `docker-compose.yml`). The same settings in `grafana.ini`.
`mock-idp` and `grafana` are the compose service names; for a Grafana outside the compose network use
`http://127.0.0.1:8081` (or your `MOCK_IDP_PUBLIC_URL`) and Grafana's own address instead:

```ini
[server]
root_url = http://grafana:3000

[auth.generic_oauth]
enabled = true
client_id = mock-idp-client
client_secret = mock-idp-secret
scopes = openid email profile
auth_url = http://mock-idp:8081/authorize
token_url = http://mock-idp:8081/token
api_url = http://mock-idp:8081/userinfo
groups_attribute_path = groups
allowed_groups = admins@example.com,devs@example.com
role_attribute_path = contains(groups[*], 'admins@example.com') && 'Admin' || 'Viewer'
```

`check.py` logs in as a member of `admins@example.com`, a member of `devs@example.com` and someone in neither, through
`/set-user` so no form is needed. It checks the role Grafana gives the first two and that the third is refused by
`allowed_groups`. The default org role is set to Editor so that Admin and Viewer can only come from the mapping. Everything talks over the compose network, so the issuer and Grafana's
`root_url` use the service names. `run.sh` combines this compose file with the root one and runs the check. CI runs it
every Monday and on demand (the `examples` workflow).
