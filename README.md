# Serveur Railway

Node.js/Express server with a fail-closed, 13-stage pre-deployment security gate.

## Local verification

```powershell
npm ci
npm run check
npm test
npm run security:licenses
npm run security:policy
npm audit --omit=dev --audit-level=high
```

The full container, SBOM, provenance, signing, IaC, secret, SAST, SCA, and OWASP ZAP checks run in [the GitHub Actions workflow](.github/workflows/security.yml). Every component is attempted and the final gate blocks the workflow unless all required stages pass.

## Railway deployment gate

1. Connect Railway to the `main` branch.
2. In the Railway service settings, enable **Wait for CI**. This dashboard setting is required; the repository cannot enable it for you.
3. Set `WEB_ADMIN_USER` and `WEB_ADMIN_PASSWORD` as Railway service variables.
4. To keep Cloudflare Turnstile enabled, also set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`. Turnstile cannot verify visitors without both Cloudflare keys.
5. Protect `main` in GitHub and require the **All 13 DevSecOps stages** status check.

Railway uses [Dockerfile](Dockerfile) and checks `/health` according to [railway.json](railway.json) and [.railway/railway.ts](.railway/railway.ts). Runtime credentials, WhatsApp sessions (`auth_info_*`), bot permissions (`allowed_*.json`), bot lists (`bots.json`), and web auth (`auth.json`) are stored on a persistent Railway Volume mounted at `/data` instead of the ephemeral container filesystem.

`SERVER_NAME`, `SERVER_ROLE`, `WHATSAPP_ENABLED`, and `ALLOWED_HOSTS` already have built-in defaults and do not need Railway variables. Cloudflare Turnstile is optional: it is enabled only when both `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are configured.

## Persistent Volume & Infrastructure as Code

Persistent storage is configured directly in code using Railway Infrastructure as Code ([`.railway/railway.ts`](.railway/railway.ts)) and [railway.json](railway.json):
- A 1024 MB volume named `data` is mounted to the service at `/data`.
- All WhatsApp authentication states, bot permissions, and administrative credentials survive restarts, crashes, and redeployments.
- On first startup with a new volume, any existing configuration files are safely migrated to `/data` without overwriting existing data.

## Web console

After signing in, select **Logs serveur** in the sidebar or open `/logs`. The authenticated, read-only console displays the application and bot output from `logs/server.log` and refreshes every two seconds. It does not expose an interactive system shell or Railway build/deployment logs.

## Documentation

The full application—website, WhatsApp bots, commands, data, Railway deployment, security, backups, and troubleshooting—is explained for non-technical readers in [docs/application-guide.pdf](docs/application-guide.pdf). Its editable source is [docs/application-guide.tex](docs/application-guide.tex).

The complete explanation, pass criteria, evidence files, and verification commands for all thirteen stages are in [docs/security-pipeline-guide.pdf](docs/security-pipeline-guide.pdf).
