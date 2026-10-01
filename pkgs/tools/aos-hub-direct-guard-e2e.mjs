// Exercises production guard journals across actual workerd process restarts.
// The launcher supplies source-built tools and a do-e2e-only Worker artifact.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] ?? "");
const dist = process.env.AOS_DIRECT_GUARD_E2E_DIST;
const executable = process.env.AOS_DIRECT_GUARD_E2E_WORKERD;
if (!process.argv[2] || !dist || !executable) throw new Error("Launcher arguments are required.");
await mkdir(root, { recursive: true, mode: 0o700 });
await mkdir(join(root, "do-storage"), { mode: 0o700 });
await writeFile(join(root, "shim.mjs"), await readFile(join(dist, "shim.mjs")), { flag: "wx" });
await writeFile(join(root, "index.wasm"), await readFile(join(dist, "index.wasm")), { flag: "wx" });
const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [ (name = "main", worker = .mainWorker),
    (name = "do-disk", disk = (path = "do-storage", writable = true)) ],
  sockets = [(name = "http", address = "127.0.0.1:8796", http = (), service = "main")]
);
const mainWorker :Workerd.Worker = (
  modules = [(name = "shim.mjs", esModule = embed "shim.mjs"),
    (name = "index.wasm", wasm = embed "index.wasm")],
  compatibilityDate = "2024-09-09", compatibilityFlags = ["nodejs_compat"],
  durableObjectNamespaces = [
    (className = "HybridObjectGuard", uniqueKey = "direct-guard-key", enableSql = true),
    (className = "HybridDirectUpload", uniqueKey = "direct-original-key", enableSql = true)
  ],
  durableObjectStorage = (localDisk = "do-disk"),
  bindings = [
    (name = "HYBRID_OBJECT_GUARD", durableObjectNamespace = "HybridObjectGuard"),
    (name = "HYBRID_DIRECT_UPLOAD", durableObjectNamespace = "HybridDirectUpload"),
    (name = "HUB_DEPLOYMENT_ID", text = "direct-guard-persisted-fixture")
  ]
);
`;
await writeFile(join(root, "worker.capnp"), config, { flag: "wx" });

const key = `.aos-direct-guard-fixture/${randomBytes(24).toString("hex")}`;
let child;
let generation = 0;
let observation = 0;

async function stop() {
  if (!child) return;
  const stopped = new Promise((done) => child.once("exit", done));
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await stopped;
  }
  child = undefined;
}

async function start() {
  generation += 1;
  const log = await open(join(root, `workerd-${generation}.log`), "wx", 0o600);
  child = spawn(executable, ["serve", "worker.capnp"], { cwd: root, stdio: ["ignore", log.fd, log.fd] });
  await log.close();
  let launchFailed = false;
  child.once("error", () => { launchFailed = true; });
  for (let attempt = 0; attempt < 240; attempt += 1) {
    if (launchFailed || child.exitCode !== null || child.signalCode !== null) throw new Error("Workerd failed before readiness; logs retained.");
    try {
      const response = await fetch("http://127.0.0.1:8796/.well-known/aos-deployment", { signal: AbortSignal.timeout(1000) });
      if (response.status === 200) return;
    } catch {}
    await new Promise((done) => setTimeout(done, 100));
  }
  throw new Error("Workerd readiness deadline elapsed; logs retained.");
}

async function probe(action) {
  observation += 1;
  const response = await fetch("http://127.0.0.1:8796/_e2e/direct-guard", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ key, action }), signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  await writeFile(join(root, `${observation}-${generation}-${action}.json`), JSON.stringify({ action, generation, status: response.status, body: text }, null, 2), { flag: "wx", mode: 0o600 });
  if (!response.ok) throw new Error(`Guard phase ${action} refused; transcript retained.`);
}

try {
  await start();
  // This real Worker has neither Native origin nor bucket bindings. A backend
  // lookup would fail; reserved public paths must exit with 404 beforehand.
  const deniedPaths = ["/.aos-direct-upload/source", "/org/.aos-direct-qualification/run",
    "/org/%2eaos-direct-upload/source", "/org%2f.aos-direct-upload%2fsource"];
  for (const [index, path] of deniedPaths.entries()) {
    const response = await fetch(`http://127.0.0.1:8796${path}`, { signal: AbortSignal.timeout(5000) });
    await writeFile(join(root, `private-namespace-${index}.json`), JSON.stringify({path,status:response.status}),
      {flag:"wx",mode:0o600});
    if (response.status !== 404) throw new Error("Reserved public namespace reached a backend.");
  }
  await probe("seed");
  await probe("unknown");
  await probe("unknown");
  await stop();
  await start();
  await probe("after_restart");
  await probe("provider_acknowledged");
  await stop();
  await start();
  await probe("lost_native_acknowledgement");
  await probe("native_acknowledged");
  await writeFile(join(root, "PASS"), "Durable original/attempt/unknown/publication/Native acknowledgement transitions passed across two process restarts.\n", { flag: "wx" });
  process.stdout.write(`PASS: retained transcripts and SQLite journals in ${root}\n`);
} finally {
  await stop();
}
