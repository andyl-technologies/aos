// Runs the actual source-built Rust mirror producer with a controlled SQLite R2
// facade. The launcher accepts only an isolated test manifest and retains every
// process log and control-byte observation. It grants no hosted acceptance.

import { spawn } from "node:child_process";
import { createServer } from "node:https";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("A retained fixture directory is required.");
const manifest = JSON.parse(await readFile(join(root, "runtime.json"), "utf8"));
for (const name of ["dist", "workerd", "tlsCertificate", "tlsKey", "providerFixture"]) {
  if (typeof manifest[name] !== "string") throw new Error(`Missing fixture tool: ${name}`);
}
if (!/^[a-f0-9]{64}$/.test(manifest.sourceDigest)) throw new Error("Invalid compiled source identity.");
if (manifest.vars.HUB_TOPOLOGY !== undefined && manifest.vars.HUB_TOPOLOGY !== "hybrid") {
  throw new Error("The controlled mirror fixture requires Hybrid topology.");
}
await mkdir(join(root, "do-storage"), { recursive: true, mode: 0o700 });
await writeFile(join(root, "shim.mjs"), await readFile(join(manifest.dist, "shim.mjs")), { flag: "wx" });
await writeFile(join(root, "index.wasm"), await readFile(join(manifest.dist, "index.wasm")), { flag: "wx" });
await writeFile(join(root, "provider.mjs"), await readFile(manifest.providerFixture), { flag: "wx" });

await writeFile(join(root, "wrapper.mjs"), await readFile(new URL("./aos-hub-mirror-runtime-worker.mjs", import.meta.url)), { flag: "wx" });
await writeFile(join(root, "upstream.mjs"), await readFile(new URL("./aos-hub-mirror-runtime-source.mjs", import.meta.url)), { flag: "wx" });
await writeFile(join(root, "guard-state.mjs"), await readFile(new URL("./aos-hub-mirror-runtime-guard-state.mjs", import.meta.url)), { flag: "wx" });

const fixtureVars = { ...manifest.vars, HUB_TOPOLOGY: "hybrid" };
const bindings = Object.entries(fixtureVars).map(([name, value]) =>
  `(name = ${JSON.stringify(name)}, text = ${JSON.stringify(value)})`);
bindings.push('(name = "HYBRID_OBJECT_GUARD", durableObjectNamespace = "HybridObjectGuard")');
bindings.push('(name = "MIRROR_FIXTURE_STORE", durableObjectNamespace = "MirrorFixtureStore")');
await writeFile(join(root, "worker.capnp"), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services=[(name="main",worker = .main),(name="upstream",worker = .upstream),
  (name="disk",disk=(path="do-storage",writable=true))],
 sockets=[(name="http",address="127.0.0.1:${manifest.workerPort}",http=(),service="main")]
);
const main :Workerd.Worker=(
 modules=[(name="wrapper.mjs",esModule=embed "wrapper.mjs"),
  (name="shim.mjs",esModule=embed "shim.mjs"),(name="index.wasm",wasm=embed "index.wasm"),
  (name="provider.mjs",esModule=embed "provider.mjs"),
  (name="guard-state.mjs",esModule=embed "guard-state.mjs")],
 compatibilityDate="2024-09-09",compatibilityFlags=["nodejs_compat"],globalOutbound="upstream",
 durableObjectNamespaces=[(className="HybridObjectGuard",uniqueKey="mirror-guard",enableSql=true),
  (className="MirrorFixtureStore",uniqueKey="mirror-provider",enableSql=true)],
 durableObjectStorage=(localDisk="disk"),bindings=[${bindings.join(",\n")}]
);
const upstream :Workerd.Worker=(modules=[(name="upstream.mjs",esModule=embed "upstream.mjs")],
 compatibilityDate="2024-09-09", bindings=[(name="UPSTREAM_SOURCES",text=${JSON.stringify(JSON.stringify(manifest.sources))})]);
`, { flag: "wx" });

let child;
let generation = 0;
const observations = [];
let observationWrites = Promise.resolve();
let loseAcknowledgement = false;
const workerOrigin = `http://127.0.0.1:${manifest.workerPort}`;

async function processResources() {
  if (!child?.pid) return null;
  try {
    const [status, stat] = await Promise.all([
      readFile(`/proc/${child.pid}/status`, "utf8"),
      readFile(`/proc/${child.pid}/stat`, "utf8"),
    ]);
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const resident = /^VmRSS:\s+(\d+) kB$/m.exec(status);
    const peak = /^VmHWM:\s+(\d+) kB$/m.exec(status);
    return {
      processResidentBytes: resident ? Number(resident[1]) * 1024 : null,
      processPeakResidentBytes: peak ? Number(peak[1]) * 1024 : null,
      processCpuTicks: Number(fields[11]) + Number(fields[12]),
    };
  } catch {
    // Unavailable accounting is reported explicitly; it cannot qualify a cap.
    return null;
  }
}

async function stop() {
  if (!child) return;
  const ended = new Promise(done => child.once("exit", done));
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await ended;
  }
  child = undefined;
}
async function start() {
  const log = await open(join(root, `workerd-${++generation}.log`), "wx", 0o600);
  child = spawn(manifest.workerd, ["serve", "worker.capnp"], { cwd: root, stdio: ["ignore", log.fd, log.fd] });
  await log.close();
  for (let attempt = 0; attempt < 240; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Workerd exited; log retained.");
    try {
      const response = await fetch(`${workerOrigin}/__fixture/memory`, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {}
    await new Promise(done => setTimeout(done, 100));
  }
  throw new Error("Workerd readiness expired; log retained.");
}
await start();
const tls = {
  cert: await readFile(manifest.tlsCertificate),
  key: await readFile(manifest.tlsKey),
};
const proxy = createServer(tls, async (request, response) => {
  let stage = "fixture-route";
  try {
    if (request.url === "/__fixture/restart" && request.method === "POST") {
      await stop();
      await start();
      response.writeHead(204);
      response.end();
      return;
    }
    if (request.url === "/__fixture/lose-ack" && request.method === "POST") {
      loseAcknowledgement = true;
      response.writeHead(204);
      response.end();
      return;
    }

    const started = performance.now();
    const requestGeneration = generation;
    const resourcesBefore = await processResources();
    const body = [];
    let requestBytes = 0;
    for await (const chunk of request) {
      requestBytes += chunk.length;
      if (requestBytes > 256 * 1024) throw new Error("Native control exceeded 256KiB");
      body.push(chunk);
    }
    const encoded = requestBytes ? Buffer.concat(body) : undefined;
    const control = encoded && ["/__hub/mirror-candidate", "/__hub/mirror-candidate-query", "/_internal/storage/v1/execute"].includes(request.url)
      ? JSON.parse(encoded) : undefined;
    const acknowledged = control?.operation?.items?.some(item => item.step.kind === "acknowledge")
      || control?.operation?.step?.kind === "acknowledge";
    const loseReply = loseAcknowledgement && acknowledged;
    if (loseReply) loseAcknowledgement = false;
    stage = "worker-fetch";
    const result = await fetch(workerOrigin + request.url, {
      method: request.method,
      headers: request.headers,
      body: encoded,
      signal: AbortSignal.timeout(600000),
    });
    response.writeHead(loseReply ? 502 : result.status, loseReply ? {} : Object.fromEntries(result.headers));
    stage = "worker-reply";
    let replyBytes = 0;
    const reply = [];
    if (result.body) for await (const chunk of result.body) {
      replyBytes += chunk.length;
      if (replyBytes > 256 * 1024) throw new Error("Worker control reply exceeded 256KiB");
      reply.push(chunk);
      if (!loseReply) response.write(chunk);
    }
    const controlWallMillis = performance.now() - started;
    let memory = { wasmBytes: null };
    try {
      memory = await (await fetch(`${workerOrigin}/__fixture/memory`)).json();
    } catch {
      // Optional accounting cannot erase the actual acknowledged control or
      // lost-reply event when a concurrent restart cancels the memory query.
    }
    const capacity = result.headers.get("x-aos-mirror-candidate-capacity");
    const buffers = result.headers.get("x-aos-mirror-candidate-buffers");
    stage = "control-observation";
    const typed = control && result.ok ? JSON.parse(Buffer.concat(reply)) : null;
    observations.push({
      generation: requestGeneration, path: request.url, status: result.status, lostReply: loseReply,
      requestBytes, replyBytes, sourceBytes: typed?.source_bytes ?? null,
      wallMillis: controlWallMillis,
      resourcesBefore, resourcesAfter: await processResources(),
      capacity: capacity ? JSON.parse(capacity) : null,
      membershipCacheKey: result.headers.get("x-aos-controlled-membership-cache-key"),
      buffers: buffers ? JSON.parse(buffers) : null,
      ...memory,
    });
    const snapshot = JSON.stringify(observations, null, 2);
    observationWrites = observationWrites.then(() =>
      writeFile(join(root, "controls.json"), snapshot, { mode: 0o600 }));
    await observationWrites;
    response.end();
  } catch {
    // Keep a value-free failure stage; an ambiguous request never becomes a
    // fabricated control result, provider effect or successful acknowledgement.
    observations.push({ generation, fixtureFailureStage: stage });
    const snapshot = JSON.stringify(observations, null, 2);
    observationWrites = observationWrites.then(() =>
      writeFile(join(root, "controls.json"), snapshot, { mode: 0o600 }));
    await observationWrites;
    if (!response.headersSent) response.writeHead(502);
    response.end();
  }
});
await new Promise(done => proxy.listen(0, "127.0.0.1", done));
await writeFile(join(root, "ready.json"), JSON.stringify({ origin: `https://localhost:${proxy.address().port}` }),
  { flag: "wx", mode: 0o600 });
process.on("SIGTERM", async () => {
  proxy.close();
  await stop();
  process.exit(0);
});
