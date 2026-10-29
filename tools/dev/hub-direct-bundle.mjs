// Builds a local development bundle using the production worker-build layout.
// Keep the module wiring aligned with pkgs/tools/aos-hub-worker-dist.nix.
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const [wasm, destination] = process.argv.slice(2).map(value => resolve(value));
if (!wasm || !destination || process.argv.length !== 4) {
  throw new Error("Expected the compiled Wasm file and a new output directory.");
}
await mkdir(destination, { mode: 0o700 });
execFileSync("wasm-bindgen", ["--target", "bundler", "--no-typescript",
  "--out-dir", destination, "--out-name", "index", wasm], { stdio: "inherit" });
await rename(join(destination, "index_bg.wasm"), join(destination, "index.wasm"));

const gluePath = join(destination, "index_bg.js");
const glue = await readFile(gluePath, "utf8");
const preamble = /let wasm;\s*export function __wbg_set_wasm\(val\)\s*\{\s*wasm = val;\s*\}/;
if (!preamble.test(glue)) throw new Error("The pinned bindgen glue preamble changed.");
await writeFile(gluePath, glue.replace(preamble, `
import __wbg_glue from './glue.js';
let wasm = __wbg_glue;
export function __wbg_set_wasm(val) { wasm = val; }
export function getMemory() { return wasm.memory; }
`));
await writeFile(join(destination, "glue.js"), `
import wasmModule from './index.wasm';
import * as imports from './index_bg.js';
const instance = new WebAssembly.Instance(wasmModule, { "./index_bg.js": imports });
export function initializeWasm() { instance.exports.__wbindgen_start(); }
export default instance.exports;
`);
await writeFile(join(destination, "shim.js"), `
import * as imports from "./index_bg.js";
export * from "./index_bg.js";
import wasmModule from "./index.wasm";
import { WorkerEntrypoint } from "cloudflare:workers";
import { initializeWasm } from "./glue.js";
initializeWasm();
imports.start?.();
export { wasmModule };
class Entrypoint extends WorkerEntrypoint {
  async fetch(request) { return await imports.fetch(request, this.env, this.ctx); }
  async queue(batch) { return await imports.queue(batch, this.env, this.ctx); }
  async scheduled(event) { return await imports.scheduled(event, this.env, this.ctx); }
}
const excluded = ["IntoUnderlyingByteSource", "IntoUnderlyingSink", "IntoUnderlyingSource",
  "MinifyConfig", "PolishConfig", "R2Range", "RequestRedirect", "fetch", "queue",
  "scheduled", "getMemory"];
for (const name of Object.keys(imports)) {
  if (!excluded.includes(name) && !name.startsWith("__")) Entrypoint.prototype[name] = imports[name];
}
export default Entrypoint;
`);
execFileSync("esbuild", ["--external:./index.wasm", "--external:cloudflare:sockets",
  "--external:cloudflare:workers", "--format=esm", "--bundle", "./shim.js",
  "--outfile=shim.mjs"], { cwd: destination, stdio: "inherit" });
