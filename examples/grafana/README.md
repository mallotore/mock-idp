# Grafana example

Logs in through a real Grafana with the mock IdP as its generic OAuth provider and checks that the `groups` claim
maps to Grafana roles. Needs only Docker:

```sh
./examples/grafana/run.sh
```

Grafana is configured with environment variables only (see `docker-compose.yml`). The same settings in `grafana.ini`:

```ini
[auth.generic_oauth]
enabled = true
client_id = mock-idp-client
client_secret = mock-idp-secret
scopes = openid email profile
auth_url = http://mock-idp:8081/authorize
token_url = http://mock-idp:8081/token
api_url = http://mock-idp:8081/userinfo
groups_attribute_path = groups
role_attribute_path = contains(groups[*], 'admins@example.com') && 'Admin' || 'Viewer'
```

`check.py` logs in as a member of `admins@example.com` and as someone else, through `/set-user` so no form is needed,
and checks the role Grafana gives each one. Everything talks over the compose network, so the issuer and Grafana's
`root_url` use the service names. `run.sh` combines this compose file with the root one and runs the check. CI runs it
every Monday and on demand (the `examples` workflow).
