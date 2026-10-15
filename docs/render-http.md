# Render HTTP deployment

REA keeps its normal MCP stdio entrypoint for local clients. Render Web Services
should use the separate HTTP entrypoint:

- **Build command:** `npm install && npm run compile`
- **Start command:** `npm run start:http`
- **Health check path:** `/health`
- **MCP endpoint:** `/mcp`
- **Runtime:** Node.js (the repository's `.nvmrc` selects the supported version)

Set `REA_HTTP_BEARER_TOKEN` in the Render service environment to a randomly
generated secret with at least 32 bytes of entropy. The HTTP runtime fails to
start if the secret is missing or too short. Send it only as an
`Authorization: Bearer <token>` header. The `/health` route is intentionally
unauthenticated and returns no application or environment details.

The HTTP adapter validates Host and Origin against localhost and Render's
`RENDER_EXTERNAL_HOSTNAME` / `RENDER_EXTERNAL_URL` values to reduce DNS-rebinding
risk. It binds to `0.0.0.0` and Render's `PORT`; do not replace these with a fixed
public port. The SDK handler serves modern per-request MCP and its legacy
stateless fallback. The process-level REA session remains shared by requests
within this single authenticated service instance.

Render's Free web services may spin down after inactivity and can have a cold
start on the next request. This is platform behavior, not an application health
failure.
