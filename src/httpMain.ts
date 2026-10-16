import { run, runEntrypoint, createRuntimeDependencies } from "./main.js";
import { serveHttp } from "./main/httpTransport.js";

export const runHttpEntrypoint = (): Promise<void> =>
  runEntrypoint(() => run(createRuntimeDependencies(serveHttp, false)));
