# Vault example

Logs in through a real Vault (dev mode) with the mock IdP as its OIDC provider and checks that group claims map to
policies. Needs only Docker:

```sh
./examples/vault/run.sh
```

`check.py` configures Vault the same way you would by hand:

```sh
vault auth enable oidc
vault write auth/oidc/config oidc_discovery_url=http://mock-idp:8081 \
  oidc_client_id=mock-idp-client oidc_client_secret=mock-idp-secret default_role=identities
vault write auth/oidc/role/identities role_type=oidc user_claim=email groups_claim=groups \
  oidc_scopes=openid,email bound_audiences=mock-idp-client \
  allowed_redirect_uris=http://localhost:8250/oidc/callback
```

`docker-compose.yml` here adds the `vault` and `vault-check` services to the root compose file. It is run manually
in CI (the `examples` workflow).
