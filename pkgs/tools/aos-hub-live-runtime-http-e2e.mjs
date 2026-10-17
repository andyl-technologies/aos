// Separately captured controlled HTTPS upstream with real socket-close evidence.
// The unchanged production stream runs in workerd; no JS body relay intervenes.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, open, readFile, readlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createLiveSocketSource } from "./aos-hub-live-runtime-http-source.mjs";

if (!process.execPath.startsWith("/nix/store/") || !process.argv[2]) {
  throw new Error("Explicit source-built Node and a private fixture directory required");
}
const root = resolve(process.argv[2]);
const manifestBytes = await readFile(join(root, "live-runtime.json"));
const manifest = JSON.parse(manifestBytes);
for (const name of ["dist", "workerd", "providerFixture", "sourceCa", "sourceCertificate", "sourceKey"]) {
  if (typeof manifest[name] !== "string" || !manifest[name].startsWith("/nix/store/")) {
    throw new Error("Pinned source-built artifacts and public fixture TLS inputs required");
  }
}
for (const name of ["sourceDigest", "wasmSha256", "shimSha256"]) {
  if (!/^[a-f0-9]{64}$/.test(manifest[name] ?? "")) throw new Error("Exact artifact commitment required");
}
if (!/^[a-f0-9]{32}$/.test(manifest.runId ?? "")
    || ![manifest.workerPort, manifest.sourcePort].every(port => Number.isInteger(port) && port >= 1024 && port <= 65535)
    || manifest.sourcePort === manifest.workerPort
    || manifest.vars.HUB_MIRROR_CANDIDATE_SOURCE_SHA256 !== manifest.sourceDigest
    || manifest.vars.HUB_MIRROR_CANDIDATE_SCRIPT_VERSION !== manifest.scriptVersion) {
  throw new Error("Closed artifact, namespace or socket pins differ");
}
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const copies = [
  ["shim.mjs", join(manifest.dist, "shim.mjs"), manifest.shimSha256],
  ["index.wasm", join(manifest.dist, "index.wasm"), manifest.wasmSha256],
  ["provider.mjs", manifest.providerFixture],
  ["wrapper.mjs", new URL("./aos-hub-live-runtime-worker.mjs", import.meta.url)],
  ["source-ca.crt", manifest.sourceCa],
  ["source.crt", manifest.sourceCertificate],
  ["source.key", manifest.sourceKey],
];
const sourceFiles = [];
for (const [name, path, expected] of copies) {
  const bytes = await readFile(path);
  if (expected && digest(bytes) !== expected) throw new Error("Selected artifact bytes changed");
  await writeFile(join(root, name), bytes, { flag: "wx", mode: 0o600 });
  sourceFiles.push({ name, sha256: digest(bytes), bytes: bytes.length });
}
await mkdir(join(root, "do-storage"), { mode: 0o700 });
const bindings = Object.entries({ ...manifest.vars, HUB_TOPOLOGY: "hybrid" }).map(([name, value]) =>
  `(name=${JSON.stringify(name)},text=${JSON.stringify(value)})`);
bindings.push('(name="HYBRID_OBJECT_GUARD",durableObjectNamespace="HybridObjectGuard")');
bindings.push('(name="MIRROR_FIXTURE_STORE",durableObjectNamespace="MirrorFixtureStore")');
await writeFile(join(root, "live-worker.capnp"), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services=[(name="main",worker = .main),
  (name="upstream",external=(address="127.0.0.1:${manifest.sourcePort}",https=(
   options=(style=host),tlsOptions=(trustBrowserCas=false,trustedCertificates=[embed "source-ca.crt"]),certificateHost="localhost"))),
  (name="disk",disk=(path="do-storage",writable=true))],
 sockets=[(name="http",address="127.0.0.1:${manifest.workerPort}",http=(),service="main")]
);
const main :Workerd.Worker=(
 modules=[(name="wrapper.mjs",esModule=embed "wrapper.mjs"),
  (name="shim.mjs",esModule=embed "shim.mjs"),(name="index.wasm",wasm=embed "index.wasm"),
  (name="provider.mjs",esModule=embed "provider.mjs")],
 compatibilityDate="2024-09-09",compatibilityFlags=["nodejs_compat","enable_request_signal"],globalOutbound="upstream",
 durableObjectNamespaces=[(className="HybridObjectGuard",uniqueKey="live-http-guard",enableSql=true),
  (className="MirrorFixtureStore",uniqueKey="live-http-provider",enableSql=true)],
 durableObjectStorage=(localDisk="disk"),bindings=[${bindings.join(",\n")}]
);
`, { flag: "wx", mode: 0o600 });

const source = createLiveSocketSource({
  runId: manifest.runId,
  cert: await readFile(join(root, "source.crt")),
  key: await readFile(join(root, "source.key")),
});
await new Promise((resolve, reject) => {
  source.server.once("error", reject);
  source.server.listen(manifest.sourcePort, "127.0.0.1", resolve);
});
await writeFile(join(root, "live-source-receipt.json"), JSON.stringify({
  manifestSha256: digest(manifestBytes), compiledSourceSha256: manifest.sourceDigest,
  scriptVersion: manifest.scriptVersion, sourceFiles,
  httpSourceSha256: digest(await readFile(new URL("./aos-hub-live-runtime-http-source.mjs", import.meta.url))),
  sourceMapping: "Canonical HTTPS Host and reserved path; fixed loopback TLS endpoint with public fixture CA and localhost peer identity",
  scope: "Controlled socket fixture and artifact identity; no Native authorization or production acceptance",
}), { flag: "wx", mode: 0o600 });

const log = await open(join(root, "live-workerd.log"), "wx", 0o600);
const child = spawn(manifest.workerd, ["serve", "live-worker.capnp"], {
  cwd: root, stdio: ["ignore", log.fd, log.fd],
});
// Register before any await so an exit during readiness/readback is retained.
const terminal = new Promise(resolve => child.once("exit", (exitCode, signal) => {
  resolve({ exitCode, signal, observedUtcMilliseconds: Date.now() });
}));
async function retainTerminal() {
  await writeFile(join(root, "live-terminal.json"), JSON.stringify(await terminal), { flag: "wx", mode: 0o600 });
}
await log.close();
const origin = `http://127.0.0.1:${manifest.workerPort}`;
let ready = false;
for (let attempt = 0; attempt < 240; attempt++) {
  if (child.exitCode !== null || child.signalCode !== null) break;
  try {
    const response = await fetch(origin + "/__fixture/live-memory", { signal: AbortSignal.timeout(500) });
    if (response.ok) { ready = true; break; }
  } catch {}
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!ready) {
  child.kill("SIGKILL");
  await retainTerminal();
  await source.close();
  throw new Error("Workerd readiness failed; all evidence retained");
}
const processStat = await readFile(`/proc/${child.pid}/stat`, "utf8");
const startTicks = processStat.slice(processStat.lastIndexOf(")") + 2).split(" ")[19];
await writeFile(join(root, "live-ready.json"), JSON.stringify({
  origin, pid: child.pid, startTicks, launcherPidNamespace: await readlink("/proc/self/ns/pid"),
}), { flag: "wx", mode: 0o600 });
process.once("SIGTERM", () => child.kill("SIGTERM"));
process.once("SIGINT", () => child.kill("SIGTERM"));
await retainTerminal();
// Teardown is explicitly excluded from qualifying any source cancellation.
await source.close();
await writeFile(join(root, "live-http-source-final.json"), JSON.stringify(source.observations()), { flag: "wx", mode: 0o600 });
