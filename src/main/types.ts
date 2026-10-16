import type { McpServerFactory } from "@modelcontextprotocol/server";
import type { ServeStdioOptions } from "@modelcontextprotocol/server/stdio";
import type { OptionalProviderLoadResult } from "../application/OptionalObservationProviders.js";

export interface RuntimeMcpHandle {
  close(): Promise<void>;
}

export type RuntimeServeOptions = Pick<ServeStdioOptions, "onerror"> & {
  readonly environment?: Readonly<NodeJS.ProcessEnv>;
};

export type RuntimeServerTransport = (
  factory: McpServerFactory,
  options: RuntimeServeOptions,
) => RuntimeMcpHandle | Promise<RuntimeMcpHandle>;

export interface RuntimeDependencies {
  readonly env: NodeJS.ProcessEnv;
  readonly serve: RuntimeServerTransport;
  readonly writeStderr: (text: string) => void;
  readonly setExitCode: (code: number) => void;
  readonly registerShutdown: (handler: () => void) => () => void;
  readonly createServer?: typeof import("../server/createServer.js").createServer;
  readonly loadOptionalProviders?: () => Promise<OptionalProviderLoadResult>;
}
