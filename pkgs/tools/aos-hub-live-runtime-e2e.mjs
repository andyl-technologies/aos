// Launches a separately rebound live candidate with actual workerd source I/O.
// No hosted evidence, review signature, Native grant or source report is created.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

if (!process.execPath.startsWith("/nix/store/")) throw new Error("A source-built Node path is required");
if (!process.argv[2]) throw new Error("A retained private fixture directory is required");
const root = resolve(process.argv[2]);
const manifestBytes = await readFile(join(root, "live-runtime.json"));
const manifest = JSON.parse(manifestBytes);
for (const field of ["dist", "workerd", "providerFixture"]) {
  if (typeof manifest[field] !== "string" || !manifest[field].startsWith("/nix/store/")) {
    throw new Error("Explicit source-built artifact paths are required");
  }
}
for (const field of ["sourceDigest", "wasmSha256", "shimSha256"]) {
  if (!/^[a-f0-9]{64}$/.test(manifest[field] ?? "")) throw new Error("An exact artifact commitment is required");
}
if (!/^[a-f0-9]{32}$/.test(manifest.runId ?? "")
    || !Number.isInteger(manifest.workerPort) || manifest.workerPort < 1024 || manifest.workerPort > 65535
    || manifest.vars.HUB_MIRROR_CANDIDATE_SOURCE_SHA256 !== manifest.sourceDigest
    || manifest.vars.HUB_MIRROR_CANDIDATE_SCRIPT_VERSION !== manifest.scriptVersion) {
  throw new Error("Closed installed source and run pins differ");
}
const digest = bytes => createHash("sha256").update(bytes).digest("hex");
const copies = [
  ["shim.mjs", join(manifest.dist, "shim.mjs"), manifest.shimSha256],
  ["index.wasm", join(manifest.dist, "index.wasm"), manifest.wasmSha256],
  ["provider.mjs", manifest.providerFixture],
  ["wrapper.mjs", new URL("./aos-hub-live-runtime-worker.mjs", import.meta.url)],
  ["upstream.mjs", new URL("./aos-hub-live-runtime-source.mjs", import.meta.url)],
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
 services=[(name="main",worker = .main),(name="upstream",worker = .upstream),
  (name="disk",disk=(path="do-storage",writable=true))],
 sockets=[(name="http",address="127.0.0.1:${manifest.workerPort}",http=(),service="main")]
);
const main :Workerd.Worker=(
 modules=[(name="wrapper.mjs",esModule=embed "wrapper.mjs"),
  (name="shim.mjs",esModule=embed "shim.mjs"),(name="index.wasm",wasm=embed "index.wasm"),
  (name="provider.mjs",esModule=embed "provider.mjs")],
 compatibilityDate="2024-09-09",compatibilityFlags=["nodejs_compat"],globalOutbound="upstream",
 durableObjectNamespaces=[(className="HybridObjectGuard",uniqueKey="live-guard",enableSql=true),
  (className="MirrorFixtureStore",uniqueKey="live-provider",enableSql=true)],
 durableObjectStorage=(localDisk="disk"),bindings=[${bindings.join(",\n")}]
);
const upstream :Workerd.Worker=(modules=[(name="upstream.mjs",esModule=embed "upstream.mjs")],
 compatibilityDate="2024-09-09",bindings=[(name="LIVE_RUN_ID",text=${JSON.stringify(manifest.runId)})]);
`, { flag: "wx", mode: 0o600 });
await writeFile(join(root, "live-source-receipt.json"), JSON.stringify({
  manifestSha256: digest(manifestBytes), compiledSourceSha256: manifest.sourceDigest,
  scriptVersion: manifest.scriptVersion, sourceFiles,
  scope: "Controlled candidate artifact identity; not production acceptance or actual runtime outcome",
}), { flag: "wx", mode: 0o600 });

const log = await open(join(root, "live-workerd.log"), "wx", 0o600);
const child = spawn(manifest.workerd, ["serve", "live-worker.capnp"], {
  cwd: root, stdio: ["ignore", log.fd, log.fd],
});
await log.close();
const origin = `http://127.0.0.1:${manifest.workerPort}`;
let ready = false;
for (let attempt = 0; attempt < 240; attempt++) {
  if (child.exitCode !== null || child.signalCode !== null) throw new Error("Workerd exited; evidence retained");
  try {
    const response = await fetch(origin + "/__fixture/live-memory", { signal: AbortSignal.timeout(500) });
    if (response.ok) { ready = true; break; }
  } catch {}
  await new Promise(resolve => setTimeout(resolve, 100));
}
if (!ready) {
  child.kill("SIGKILL");
  throw new Error("Workerd readiness expired; evidence retained");
}
const processStat = await readFile(`/proc/${child.pid}/stat`, "utf8");
const startTicks = processStat.slice(processStat.lastIndexOf(")") + 2).split(" ")[19];
await writeFile(join(root, "live-ready.json"), JSON.stringify({ origin, pid: child.pid, startTicks }), { flag: "wx", mode: 0o600 });
process.once("SIGTERM", () => child.kill("SIGTERM"));
process.once("SIGINT", () => child.kill("SIGTERM"));
await new Promise(resolve => child.once("exit", resolve));
