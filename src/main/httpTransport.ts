import {
  createMcpHandler,
  hostHeaderValidationResponse,
  localhostAllowedHostnames,
} from "@modelcontextprotocol/server";
import type { McpServerFactory } from "@modelcontextprotocol/server";
import cors from "cors";
import { timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { RuntimeMcpHandle, RuntimeServerTransport } from "./types.js";

const HTTP_TOKEN_ENV = "REA_HTTP_BEARER_TOKEN";
const MINIMUM_TOKEN_BYTES = 32;
const DEFAULT_PORT = 10_000;
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

type McpHttpHandler = ReturnType<typeof createMcpHandler>;

export const applyCors = cors({
  origin: "*",
  methods: ["GET", "HEAD", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Accept",
    "Authorization",
    "Content-Type",
    "Last-Event-ID",
    "MCP-Protocol-Version",
    "MCP-Session-Id",
  ],
  exposedHeaders: ["MCP-Protocol-Version", "MCP-Session-Id"],
  maxAge: 86_400,
  optionsSuccessStatus: 204,
});

const validatedToken = (environment: Readonly<NodeJS.ProcessEnv>): Buffer => {
  const token = environment[HTTP_TOKEN_ENV];
  if (token === undefined || Buffer.byteLength(token) < MINIMUM_TOKEN_BYTES)
    throw new Error(`${HTTP_TOKEN_ENV} must contain at least 32 bytes`);
  return Buffer.from(token);
};

const matchesBearerToken = (authorization: string | null, expected: Buffer) => {
  if (authorization === null) return false;
  const match = /^Bearer\s+([^\s]+)$/iu.exec(authorization);
  const suppliedToken = match?.[1];
  if (suppliedToken === undefined) return false;
  const supplied = Buffer.from(suppliedToken);
  return (
    supplied.length === expected.length && timingSafeEqual(supplied, expected)
  );
};

const jsonResponse = (status: number, body: unknown): Response =>
  Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });

const trustedHostnames = (environment: Readonly<NodeJS.ProcessEnv>) => {
  const hostnames = new Set(localhostAllowedHostnames());
  const configuredHost = environment.RENDER_EXTERNAL_HOSTNAME;
  if (configuredHost !== undefined && configuredHost.length > 0)
    hostnames.add(configuredHost.toLowerCase());
  const externalUrl = environment.RENDER_EXTERNAL_URL;
  if (externalUrl !== undefined) {
    try {
      hostnames.add(new URL(externalUrl).hostname.toLowerCase());
    } catch {
      // An invalid optional platform URL does not widen the allowlist.
    }
  }
  return [...hostnames];
};

export const createMcpHttpRequestHandler = (
  handler: McpHttpHandler,
  environment: Readonly<NodeJS.ProcessEnv>,
): ((request: Request) => Promise<Response>) => {
  const token = validatedToken(environment);
  const allowedHosts = trustedHostnames(environment);

  return async (request) => {
    const url = new URL(request.url);
    if (
      url.pathname === "/health" &&
      (request.method === "GET" || request.method === "HEAD")
    )
      return request.method === "HEAD"
        ? new Response(null, {
            status: 200,
            headers: { "cache-control": "no-store" },
          })
        : jsonResponse(200, { status: "ok" });

    if (url.pathname !== "/mcp" && url.pathname !== "/mcp/")
      return jsonResponse(404, { error: "not_found" });

    const validationHeaders = new Headers(request.headers);
    if (!validationHeaders.has("host")) validationHeaders.set("host", url.host);
    const validationRequest = new Request(url, { headers: validationHeaders });
    const invalidHost = hostHeaderValidationResponse(
      validationRequest,
      allowedHosts,
    );
    if (invalidHost !== undefined) return invalidHost;
    if (!matchesBearerToken(request.headers.get("authorization"), token))
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: {
          "cache-control": "no-store",
          "content-type": "application/json; charset=utf-8",
          "www-authenticate": 'Bearer realm="rea-mcp"',
        },
      });

    return handler.fetch(request);
  };
};

const requestFromNode = (
  incoming: IncomingMessage,
  environment: Readonly<NodeJS.ProcessEnv>,
  signal: AbortSignal,
): Request => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined || HOP_BY_HOP_HEADERS.has(name.toLowerCase()))
      continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  const host = headers.get("host") ?? "localhost";
  const hostname = new URL(`http://${host}`).hostname.toLowerCase();
  const renderHostname = environment.RENDER_EXTERNAL_HOSTNAME?.toLowerCase();
  const scheme =
    renderHostname !== undefined && hostname === renderHostname
      ? "https:"
      : "http:";
  const url = new URL(incoming.url ?? "/", `${scheme}//${host}`);
  const method = incoming.method ?? "GET";
  const body =
    method === "GET" || method === "HEAD"
      ? undefined
      : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>);
  const init = {
    method,
    headers,
    signal,
    ...(body === undefined ? {} : { body, duplex: "half" }),
  } as RequestInit;
  return new Request(url, init);
};

const writeWebResponse = async (
  response: Response,
  outgoing: ServerResponse,
): Promise<void> => {
  outgoing.statusCode = response.status;
  response.headers.forEach((value, name) => outgoing.setHeader(name, value));
  if (response.body === null) {
    outgoing.end();
    return;
  }
  await pipeline(Readable.fromWeb(response.body), outgoing);
};

const listen = (
  server: ReturnType<typeof createServer>,
  port: number,
  host: string,
): Promise<void> =>
  new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

const closeServer = (server: ReturnType<typeof createServer>): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });

const readPort = (environment: Readonly<NodeJS.ProcessEnv>): number => {
  const raw = environment.PORT ?? String(DEFAULT_PORT);
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error("PORT must be an integer between 0 and 65535");
  return port;
};

export const serveHttp: RuntimeServerTransport = async (
  factory: McpServerFactory,
  options,
): Promise<RuntimeMcpHandle> => {
  const environment = options.environment ?? process.env;
  const port = readPort(environment);
  const host = environment.REA_HTTP_HOST ?? "0.0.0.0";
  const mcpHandler = createMcpHandler(factory, {
    legacy: "stateless",
    ...(options.onerror === undefined ? {} : { onerror: options.onerror }),
  });
  let dispatch: (request: Request) => Promise<Response>;
  try {
    dispatch = createMcpHttpRequestHandler(mcpHandler, environment);
  } catch (cause) {
    await mcpHandler.close();
    throw cause;
  }

  const server = createServer((incoming, outgoing) => {
    applyCors(incoming, outgoing, (corsError) => {
      if (corsError) {
        options.onerror?.(
          corsError instanceof Error
            ? corsError
            : new Error("CORS middleware failed"),
        );
        outgoing.statusCode = 500;
        outgoing.end();
        return;
      }
      if (outgoing.writableEnded) return;

      const controller = new AbortController();
      incoming.once("aborted", () => controller.abort());
      outgoing.once("close", () => {
        if (!outgoing.writableEnded) controller.abort();
      });
      void (async () => {
        try {
          const request = requestFromNode(
            incoming,
            environment,
            controller.signal,
          );
          await writeWebResponse(await dispatch(request), outgoing);
        } catch (cause) {
          options.onerror?.(
            cause instanceof Error ? cause : new Error("HTTP request failed"),
          );
          if (!outgoing.headersSent) {
            outgoing.statusCode = 500;
            outgoing.setHeader("cache-control", "no-store");
            outgoing.setHeader(
              "content-type",
              "application/json; charset=utf-8",
            );
            outgoing.end(JSON.stringify({ error: "internal_server_error" }));
          } else if (!outgoing.destroyed) {
            outgoing.destroy();
          }
        }
      })();
    });
  });

  try {
    await listen(server, port, host);
  } catch (cause) {
    await mcpHandler.close();
    throw cause;
  }

  let closePromise: Promise<void> | undefined;
  return {
    close: () => {
      closePromise ??= (async () => {
        let closeError: unknown;
        try {
          await closeServer(server);
        } catch (cause) {
          closeError = cause;
        }
        try {
          await mcpHandler.close();
        } catch (cause) {
          if (closeError !== undefined)
            throw new AggregateError(
              [closeError, cause],
              "HTTP cleanup failed",
            );
          throw cause;
        }
        if (closeError !== undefined) throw closeError;
      })();
      return closePromise;
    },
  };
};
