import { createServer } from "node:http";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyCors,
  createMcpHttpRequestHandler,
} from "../../../src/main/httpTransport.js";

describe("MCP HTTP request handler", () => {
  const token = "a".repeat(64);
  const fetchMock = vi.fn(
    async () => new Response("mcp-response", { status: 200 }),
  );
  const handler = {
    fetch: fetchMock,
    close: vi.fn(async () => undefined),
    notify: vi.fn(),
    bus: {},
  } as unknown as Parameters<typeof createMcpHttpRequestHandler>[0];
  const apkAnalysis = vi.fn(
    async () => Response.json({ analysis: "manifest answer" }),
  );
  const cancelAll = vi.fn(() => 2);
  Object.assign(apkAnalysis, { cancelAll });
  const app = createMcpHttpRequestHandler(
    handler,
    { REA_HTTP_BEARER_TOKEN: token },
    apkAnalysis,
  );

  beforeEach(() => {
    fetchMock.mockClear();
    apkAnalysis.mockClear();
    cancelAll.mockClear();
  });

  it("exposes a minimal unauthenticated health check", async () => {
    const response = await app(new Request("http://localhost/health"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires a bearer token for the MCP endpoint", async () => {
    const response = await app(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: { host: "localhost", "content-type": "application/json" },
        body: "{}",
      }),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("Bearer");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards an authenticated request from any Origin to the SDK handler", async () => {
    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        host: "localhost",
        origin: "https://frontend.example",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    const response = await app(request);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("mcp-response");
    expect(fetchMock).toHaveBeenCalledWith(request);
  });

  it("protects APK analysis with the bearer token and dispatches POST", async () => {
    const request = new Request("http://localhost/api/analyze-apk", {
      method: "POST",
      headers: {
        host: "localhost",
        authorization: `Bearer ${token}`,
        "content-type": "multipart/form-data; boundary=test",
      },
      body: "--test--\r\n",
    });
    const response = await app(request);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ analysis: "manifest answer" });
    expect(apkAnalysis).toHaveBeenCalledWith(request);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects unauthenticated APK uploads and non-POST methods", async () => {
    const unauthorized = await app(
      new Request("http://localhost/api/analyze-apk", {
        method: "POST",
        headers: { host: "localhost" },
      }),
    );
    expect(unauthorized.status).toBe(401);

    const methodNotAllowed = await app(
      new Request("http://localhost/api/analyze-apk", {
        method: "GET",
        headers: {
          host: "localhost",
          authorization: `Bearer ${token}`,
        },
      }),
    );
    expect(methodNotAllowed.status).toBe(405);
    expect(methodNotAllowed.headers.get("allow")).toContain("POST");
    expect(apkAnalysis).not.toHaveBeenCalled();
  });

  it("protects cancel-all with the bearer token and accepts POST only", async () => {
    const unauthorized = await app(
      new Request("http://localhost/api/cancel-analyses", {
        method: "POST",
        headers: { host: "localhost" },
      }),
    );
    expect(unauthorized.status).toBe(401);
    expect(cancelAll).not.toHaveBeenCalled();

    const methodNotAllowed = await app(
      new Request("http://localhost/api/cancel-analyses", {
        method: "GET",
        headers: {
          host: "localhost",
          authorization: `Bearer ${token}`,
        },
      }),
    );
    expect(methodNotAllowed.status).toBe(405);

    const response = await app(
      new Request("http://localhost/api/cancel-analyses", {
        method: "POST",
        headers: {
          host: "localhost",
          authorization: `Bearer ${token}`,
        },
      }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ cancelled: 2 });
    expect(cancelAll).toHaveBeenCalledTimes(1);
  });

  it("rejects an untrusted Host header while retaining Origin-independent CORS policy", async () => {
    const untrustedHost = await app(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: {
          host: "attacker.example",
          origin: "https://frontend.example",
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: "{}",
      }),
    );
    expect(untrustedHost.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("allows any browser Origin and handles MCP preflight requests", async () => {
    const server = createServer((request, response) => {
      applyCors(request, response, () => response.end("ok"));
    });
    server.listen(0, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Test HTTP server did not bind to a TCP port");

    try {
      const preflight = await fetch(`http://127.0.0.1:${address.port}/mcp`, {
        method: "OPTIONS",
        headers: {
          Origin: "https://unrelated-frontend.example",
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers":
            "authorization,content-type,mcp-protocol-version",
        },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-origin")).toBe("*");
      expect(preflight.headers.get("access-control-allow-methods")).toContain(
        "POST",
      );
      expect(preflight.headers.get("access-control-allow-headers")).toContain(
        "Authorization",
      );
      expect(preflight.headers.get("access-control-allow-credentials")).toBe(
        null,
      );

      const actual = await fetch(`http://127.0.0.1:${address.port}/health`, {
        headers: { Origin: "https://another-frontend.example" },
      });
      expect(actual.status).toBe(200);
      expect(actual.headers.get("access-control-allow-origin")).toBe("*");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  it("fails closed when the bearer secret is missing or too short", () => {
    expect(() => createMcpHttpRequestHandler(handler, {})).toThrow(
      /REA_HTTP_BEARER_TOKEN/u,
    );
    expect(() =>
      createMcpHttpRequestHandler(handler, { REA_HTTP_BEARER_TOKEN: "short" }),
    ).toThrow(/32 bytes/u);
  });
});
