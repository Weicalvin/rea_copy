import { beforeEach, describe, expect, it, vi } from "vitest";

import { createMcpHttpRequestHandler } from "../../../src/main/httpTransport.js";

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
  const app = createMcpHttpRequestHandler(handler, {
    REA_HTTP_BEARER_TOKEN: token,
  });

  beforeEach(() => fetchMock.mockClear());

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

  it("forwards an authenticated request to the SDK handler", async () => {
    const request = new Request("http://localhost/mcp", {
      method: "POST",
      headers: {
        host: "localhost",
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

  it("rejects untrusted Host and Origin headers", async () => {
    const untrustedHost = await app(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: {
          host: "attacker.example",
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: "{}",
      }),
    );
    expect(untrustedHost.status).toBe(403);

    const untrustedOrigin = await app(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: {
          host: "localhost",
          origin: "https://attacker.example",
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: "{}",
      }),
    );
    expect(untrustedOrigin.status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
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
