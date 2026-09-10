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
3. Set real `WEB_ADMIN_USER`, `WEB_ADMIN_PASSWORD`, `TURNSTILE_SITE_KEY`, and `TURNSTILE_SECRET_KEY` Railway variables.
4. Protect `main` in GitHub and require the **All 13 DevSecOps stages** status check.

Railway uses [Dockerfile](Dockerfile) and checks `/health` according to [railway.json](railway.json). Runtime credentials and WhatsApp state are excluded from the container build context.

## Documentation

The complete explanation, pass criteria, evidence files, and verification commands for all thirteen stages are in [docs/security-pipeline-guide.pdf](docs/security-pipeline-guide.pdf).
