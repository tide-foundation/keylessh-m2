# KeyleSSH Azure Deployment (demo / devops / staging)

Operational guide for the hosted KeyleSSH environments in the **`KeyleSSH`** Azure
resource group (subscription *Tide Azure Sponsorship*, region `australiaeast`).

For the generic, component-level guide (TideCloak, signal server, VPN, TideSSP) see
[../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md). This doc is specifically about the
three hosted environments and the day-to-day operations on them.

---

## Environments at a glance

| Env | Web app (App Service) | Custom domain | Gateway (ACI) | `GATEWAY_ID` | Identity server | Realm / client |
|-----|-----------------------|---------------|---------------|--------------|-----------------|----------------|
| **demo** | `KeyleSSH` | demo.keylessh.com | `punchd-gateway` | `Tide-GW` | **prod** `login.dauth.me` | `keylessh-demo` / `keylessh-demo-client` |
| **devops** | `keylessh-devops` | devops.keylessh.com | `punchd-gateway-devops` | `Devops-GW` | `login.dauth.me` | `keylessh-demo-01` / `myclient` |
| **staging** | `keylessh-staging` | staging.keylessh.com | `punchd-gateway-staging` | `Staging-GW` | **staging** `staging.dauth.me` | `keylessh` / `keylessh-client` |

- All web apps run **`NODE|22-lts`** (must match CI's Node 22 — native `better-sqlite3`
  is ABI-locked; a mismatch crash-loops the app). See *Gotchas*.
- All gateways use the **shared signal server** `wss://punchd.keylessh.com`
  (`EXTERNAL_IP=20.211.145.216`), so they share `API_SECRET` / `TURN_SECRET`.
- ACI public/egress IPs are **ephemeral** (change on every recreate); the FQDN is
  preserved via the DNS name label.

---

## Where each component gets its TideCloak config

Understanding this is the key to deploying correctly.

- **Web app – server side** (`server/lib/auth/tidecloakConfig.ts` `GetConfig()`):
  uses `process.env.TIDECLOAK_CONFIG` **if set**, otherwise reads
  `data/tidecloak.json` from the deploy package (`wwwroot/data`).
  - **demo** → config comes from the **`TIDECLOAK_CONFIG` app setting** (env var).
  - **devops / staging** → config is **baked into the build**: the workflow copies
    `data/tidecloak.devops.json` (devops) or `data/tidecloak.staging.json` (staging) into
    the package.
- **Web app – client side**: the browser fetches the config at runtime from
  **`GET /api/auth/config`** (which returns `GetConfig()`), so it is **not** baked into
  the JS bundle. **Verify a deploy by curling `/api/auth/config`, not by diffing bundles.**
- **Gateway (ACI)**: reads the adapter from the **`TIDECLOAK_CONFIG_B64`** env var
  (base64 of the adapter JSON). It verifies each user token: `iss` must be
  `<auth-server-url>/realms/<realm>`, **`azp` must equal `resource`**, `exp` valid, and
  signature must verify against the embedded `jwk`. If the realm's client id or signing
  key changes, the gateway must be recreated with the new adapter or it rejects tokens
  with `AZP mismatch` / `JWT verification failed`.

Committed adapter files: `data/tidecloak.devops.json` (devops),
`data/tidecloak.staging.json` (staging), `data/tidecloak.demo.json` (demo). `data/` is
gitignored, so these are **force-added** (`git add -f`). `data/tidecloak.json` is the
legacy fallback (used only if no `data/tidecloak.<env>.json` exists).

---

## Deploy tooling

### `azure/deploy-devops.sh` (parameterized by `DEPLOY_ENV`)

```bash
DEPLOY_ENV=<env> ./azure/deploy-devops.sh [--setup | --webapp | --gateway | --all]
```

- `DEPLOY_ENV` (default `devops`) selects `azure/.env.<env>` + `azure/.env.<env>.local`
  and the default resource names, and auto-selects `data/tidecloak.<env>.json` when present.
- `--setup` creates/*reconfigures* the web app (App Service) and uploads config to its
  file share. `--gateway` (re)creates the Punchd Gateway ACI. `--webapp` builds+deploys
  web-app code locally. `--all` = webapp + gateway.
- ⚠️ **`--webapp` builds `better-sqlite3` for the local OS.** On Windows that produces a
  Windows binary that crash-loops on Azure Linux — **deploy web-app code via GitHub
  Actions instead** (below). `--gateway` and `--setup` are pure `az` and safe from any OS.

### GitHub Actions (web-app code, Linux build) — `tide-foundation/keylessh-m2`

| Env | Workflow | Publish-profile secret | Config baked |
|-----|----------|------------------------|--------------|
| demo | `azure-deploy.yml` | `AZURE_WEBAPP_PUBLISH_PROFILE` | none (uses env var) |
| devops | `azure-deploy-devops.yml` | `AZURE_WEBAPP_DEVOPS_PUBLISH_PROFILE` | `data/tidecloak.devops.json` |
| staging | `azure-deploy-staging.yml` | `AZURE_WEBAPP_STAGING_PUBLISH_PROFILE` | `data/tidecloak.staging.json` |

```bash
gh workflow run <workflow>.yml -R tide-foundation/keylessh-m2
```

A publish-profile secret can be (re)minted from Azure:

```bash
az webapp deployment list-publishing-profiles --name <APP> --resource-group KeyleSSH --xml \
  | gh secret set <SECRET_NAME> -R tide-foundation/keylessh-m2
```

---

## Common operations

### A. Deploy / refresh web-app code

```bash
gh workflow run azure-deploy.yml         -R tide-foundation/keylessh-m2   # demo (KeyleSSH)
gh workflow run azure-deploy-staging.yml -R tide-foundation/keylessh-m2   # staging
gh workflow run azure-deploy-devops.yml  -R tide-foundation/keylessh-m2   # devops
```

Verify: `curl -s https://<domain>/ | grep -o '/assets/index-[^"]*\.js'` (bundle hash) and
`curl -s https://<domain>/api/auth/config | jq '{realm,resource}'`.

### B. Recreate a gateway

```bash
DEPLOY_ENV=staging ./azure/deploy-devops.sh --gateway
DEPLOY_ENV=demo    ./azure/deploy-devops.sh --gateway
```

Verify: `az container logs -g KeyleSSH -n <gateway>` → look for `TideCloak JWKS loaded
successfully`, the correct `Valid issuers`, and `Registered as gateway`.

### C. Rotate a Tide adapter (the recurring task)

When Tide re-provisions a realm (new VVK → new `kid`/`vendorId`, or a client rename), the
whole environment must be updated with the new adapter. **A key rotation invalidates all
existing sessions — users must log in again.**

**staging** (config baked into the build):
1. Save the new adapter to `data/tidecloak.staging.json`; `jq empty` to validate; confirm
   it contains `client-origin-auth-https://staging.keylessh.com`.
2. `DEPLOY_ENV=staging ./azure/deploy-devops.sh --gateway`
3. `git add -f data/tidecloak.staging.json && git commit && git push`
4. `gh workflow run azure-deploy-staging.yml -R tide-foundation/keylessh-m2`
5. Verify `curl https://staging.keylessh.com/api/auth/config`.

**demo** (config in the web app env var):
1. Update the `KeyleSSH` web app's **`TIDECLOAK_CONFIG`** app setting with the new adapter
   (preserve the app-custom `stun-server-client-id` field), then `az webapp restart`.
2. Save the same adapter to `data/tidecloak.demo.json` and
   `DEPLOY_ENV=demo ./azure/deploy-devops.sh --gateway` to refresh the gateway.
3. `git add -f data/tidecloak.demo.json && git commit && git push`.
4. Verify `curl https://demo.keylessh.com/api/auth/config`.

Set the demo web app config via a JSON settings file (avoids shell-quoting the big value):
```bash
jq -n --arg v "$(jq -c '{"stun-server-client-id":"myclient-stun"} + .' new-adapter.json)" \
  '{TIDECLOAK_CONFIG:$v}' > settings.json
az webapp config appsettings set --name KeyleSSH --resource-group KeyleSSH --settings @settings.json
az webapp restart --name KeyleSSH --resource-group KeyleSSH
```

---

## Secrets

- **Signal server** (shared, `punchd.keylessh.com`): `API_SECRET`, `TURN_SECRET`,
  `EXTERNAL_IP=20.211.145.216` — live in `azure/.env.<env>.local` (gitignored). The same
  values are used by every gateway.
- **App Service publish profiles**: GitHub repo secrets (table above). Long-lived deploy
  credentials — fetchable from Azure any time with `az webapp deployment
  list-publishing-profiles`.
- **TideCloak admin (staging)**: `staging.dauth.me` master realm `admin` / `admin-cli`
  (used for diagnostics). Prod `login.dauth.me` admin is Tide-managed.

---

## Gotchas (learned the hard way)

- **`NODE|22-lts` is mandatory.** CI builds `better-sqlite3` on Node 22
  (`NODE_MODULE_VERSION 127`). If the App Service runtime is Node 20 the app crash-loops
  with `ERR_DLOPEN_FAILED`. Check with `az webapp config show --query linuxFxVersion`.
- **Static JWK, no live JWKS.** The server verifies tokens against the single `jwk` in its
  config (`createLocalJWKSet`), and the gateway against its embedded `jwk`. So **every Tide
  key rotation requires a redeploy** (gateway recreate + web-app config update). A future
  improvement is verifying against the realm's live `…/protocol/openid-connect/certs` with
  a static fallback, which would make rotations a no-op.
- **Token-expiry blips.** Access-token lifespan is short (~10 min) and the client polls; a
  poll landing in the expiry gap 401s until the silent refresh completes, then recovers.
  Mitigation: refresh-and-retry-on-401 in `client/src/lib/appFetch.ts`.
- **IGA / ORK realm state.** Tide realms with IGA enabled require every token-contributing
  unit (client mappers, `client_scope_assignment_set`) to carry a VVK signature, and the
  ORK enforces a "uniform replay" `aud` — these surface as `500` on the token endpoint or
  `TIDE-ORK-ATTESTATION-INVALID`, and are fixed on the Tide/realm side, not here.
- **`auth-server-url` trailing slash.** Exports sometimes include a trailing `/`. Harmless
  server-side (code strips it) but can double-slash client SDK URLs — watch for
  `dauth.me//realms/...` if login misbehaves.
- **demo is a hybrid.** Its web app config is an **env var** (not a baked file), and its
  gateway/web-app names don't follow the `-demo` suffix convention (they're `punchd-gateway`
  / `KeyleSSH`). `azure/.env.demo` encodes these overrides; do **not** run `--setup`/`--webapp`
  with `DEPLOY_ENV=demo`.
