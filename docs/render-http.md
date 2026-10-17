# Render HTTP deployment

REA keeps its normal MCP stdio entrypoint for local clients. Render Web Services
should use the separate HTTP entrypoint:

- **Build command:** `npm install && npm run compile`
- **Start command:** `npm run start:http`
- **Health check path:** `/health`
- **MCP endpoint:** `/mcp`
- **APK analysis endpoint:** `POST /api/analyze-apk`
- **Cancel all APK analyses:** `POST /api/cancel-analyses`
- **Runtime:** Node.js (the repository's `.nvmrc` selects the supported version)

Set `REA_HTTP_BEARER_TOKEN` in the Render service environment to a randomly
generated secret with at least 32 bytes of entropy. The HTTP runtime fails to
start if the secret is missing or too short. Send it only as an
`Authorization: Bearer <token>` header. The `/health` route is intentionally
unauthenticated and returns no application or environment details.

The HTTP adapter allows browser requests from any Origin (`Access-Control-Allow-Origin: *`)
and handles CORS preflight requests, including the MCP authorization and protocol
headers. Cookie credentials are not enabled. The MCP endpoint still requires the
Bearer token, and the adapter continues to validate Host against localhost and
Render's `RENDER_EXTERNAL_HOSTNAME` / `RENDER_EXTERNAL_URL` values to reduce
DNS-rebinding risk. It binds to `0.0.0.0` and Render's `PORT`; do not replace
these with a fixed public port. The SDK handler serves modern per-request MCP
and its legacy stateless fallback. The process-level REA session remains shared
by requests within this single authenticated service instance.

## APK upload and Groq analysis

The mobile client uploads an APK as `multipart/form-data` to
`https://<RENDER_EXTERNAL_HOSTNAME>/api/analyze-apk` with the same Bearer token:

- `file`: one `.apk` file, maximum **100 MiB**.
- `question`: one custom question, maximum **4,000 characters / 8 KiB**.

The server streams the file to a private temporary directory, checks ZIP entry
count and the uncompressed root `AndroidManifest.xml` size (maximum 2 MiB), then
uses the pure-Node `adbkit-apkreader` parser to extract bounded manifest fields.
It sends only the normalized manifest summary and question to Groq and deletes
the temporary file after the request. The endpoint accepts only one analysis at
a time per service instance and returns HTTP 429 while busy. A stalled analysis
is aborted after 120 seconds, and the active slot is released during cleanup.
The authenticated `POST /api/cancel-analyses` endpoint cancels all active APK
analyses on the current service instance and returns `{ "cancelled": <count> }`.
Only use it when you intend to stop every in-progress APK analysis for this
service. It does not execute the APK and does not use JDK, JADX, or DEX analysis
on Render.

The successful response is JSON, for example:

```json
{
  "analysis": "根據 Manifest，此 APK 宣告了網路與相機權限……",
  "apk": {
    "fileName": "sample.apk",
    "packageName": "org.example.demo",
    "versionName": "1.4.2",
    "versionCode": 14,
    "minSdkVersion": 23,
    "targetSdkVersion": 35,
    "permissions": ["android.permission.INTERNET"]
  }
}
```

In the Render service dashboard, open **Environment** and set these variables:

| Name | Value |
| --- | --- |
| `REA_HTTP_BEARER_TOKEN` | Generate a secret with at least 32 bytes of entropy, for example `openssl rand -hex 32`. Keep it private. |
| `GROQ_API_KEY` | Your Groq API key. Mark it secret; never put it in Expo `EXPO_PUBLIC_*` variables or commit it. |
| `GROQ_MODEL` | Optional. Defaults to `openai/gpt-oss-20b`; set another model ID supported by your Groq account if needed. |

Save the environment changes so Render restarts/redeploys the service. The Groq
OpenAI-compatible base URL is `https://api.groq.com/openai/v1`. Models, quotas,
and pricing can change; check the [Groq model list](https://console.groq.com/docs/models)
and your account's current usage before enabling requests. Do not assume a model
or API key will always be free.

The mobile client calls the full path with `POST`, sends `Authorization: Bearer
<REA_HTTP_BEARER_TOKEN>`, and submits the fields `file` and `question`. When using
React Native `FormData`, do **not** set `Content-Type` manually; the runtime must
add the multipart boundary. The app asks for the URL and token once and stores
them with Expo SecureStore. For public distribution, a shared client token is
not a substitute for per-user authentication because a user controlling their
device can ultimately recover a client-held token.

The configured HTTP adapter still supports CORS preflight (`OPTIONS`) and allows
the upload request headers without enabling cookie credentials. Render's Free
web services may spin down after inactivity and have a cold start on the next
request; an upload may take longer while the service wakes.

Render's Free web services may spin down after inactivity and can have a cold
start on the next request. This is platform behavior, not an application health
failure.
