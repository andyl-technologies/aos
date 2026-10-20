// Runs only the feature-gated byte helper with a controlled TLS provider.
// Guard originals, leases, business settlement and hosted providers are outside
// this gate; request cancellation and native transfer use the actual Worker.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { join, resolve } from "node:path";
import { createCopySource, sourceBytes, sourceSha256 } from "./aos-hub-external-copy-stream-source.mjs";

if (!process.execPath.startsWith("/nix/store/") || process.argv.length !== 6) {
  throw new Error("Source-built Node requires fixture directory, dist, workerd and tracked TLS directory");
}
const [root, dist, workerd, tls] = process.argv.slice(2).map(value => resolve(value));
assert(workerd.startsWith("/nix/store/"));
const workerPort = 18137;
const sourcePort = 18138;
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
await mkdir(root, { mode: 0o700 });
const files = [];
for (const [name, path] of [
  ["shim.mjs", join(dist, "shim.mjs")], ["index.wasm", join(dist, "index.wasm")],
  ["source-ca.crt", join(tls, "hub-hybrid-fleet-s3-ca.crt")],
  ["source.crt", join(tls, "hub-hybrid-fleet-s3.crt")],
  ["source.key", join(tls, "hub-hybrid-fleet-s3.key")],
]) {
  const bytes = await readFile(path);
  await writeFile(join(root, name), bytes, { flag: "wx", mode: 0o600 });
  files.push({ name, sha256: hash(bytes), bytes: bytes.length });
}
const config = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
 services=[(name="main",worker = .main),
  (name="provider",external=(address="127.0.0.1:${sourcePort}",https=(
   options=(style=host),certificateHost="s3.fleet.test",
   tlsOptions=(trustBrowserCas=false,trustedCertificates=[embed "source-ca.crt"]))))],
 sockets=[(name="http",address="127.0.0.1:${workerPort}",http=(),service="main")]
);
const main :Workerd.Worker = (
 modules=[(name="shim.mjs",esModule=embed "shim.mjs"),(name="index.wasm",wasm=embed "index.wasm")],
 compatibilityDate="2024-09-09",compatibilityFlags=["nodejs_compat","enable_request_signal"],
 globalOutbound="provider",bindings=[(name="HUB_TOPOLOGY",text="hybrid"),
  (name="HUB_DEPLOYMENT_ID",text="controlled-copy-stream")]
);
`;
await writeFile(join(root, "worker.capnp"), config, { flag: "wx", mode: 0o600 });
const source = createCopySource({ cert: await readFile(join(root, "source.crt")),
  key: await readFile(join(root, "source.key")) });
await new Promise((resolve, reject) => {
  source.server.once("error", reject);
  source.server.listen(sourcePort, "127.0.0.1", resolve);
});
const log = await open(join(root, "workerd.log"), "wx", 0o600);
const child = spawn(workerd, ["serve", "worker.capnp"], {
  cwd: root, stdio: ["ignore", log.fd, log.fd],
});
let exit;
const terminal = new Promise(resolve => child.once("exit", (code, signal) => {
  exit = { code, signal }; resolve(exit);
}));
const waitFor = async (condition, milliseconds = 5000) => {
  const deadline = Date.now() + milliseconds;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Bounded observation deadline elapsed");
    await new Promise(resolve => setTimeout(resolve, 25));
  }
};
const control = (scenario, signal) => fetch(`http://127.0.0.1:${workerPort}/_e2e/external-copy-stream`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ scenario }), signal,
});
const results = [];
try {
  let ready = false;
  for (let attempt = 0; attempt < 100 && !ready; attempt++) {
    if (exit) throw new Error("Worker exited before readiness");
    try { await fetch(`http://127.0.0.1:${workerPort}/`); ready = true; }
    catch { await new Promise(resolve => setTimeout(resolve, 50)); }
  }
  assert(ready, "Worker readiness");
  for (const scenario of ["positive", "replacement", "truncate", "wrong_second", "early_reject", "stall"]) {
    const started = Date.now();
    const response = await control(scenario, AbortSignal.timeout(10000));
    const body = await response.text();
    if (scenario === "positive") {
      assert.equal(response.status, 200, body);
      const value = JSON.parse(body);
      assert.equal(value.sha256, sourceSha256);
      assert.equal(value.bytes, sourceBytes);
      assert.equal(value.etag, '"controlled-part-tag"');
      assert.equal(value.providerPeak, 2);
      assert.equal(source.snapshot(scenario).positives, 1);
    } else {
      assert.equal(response.status, 409, body);
      assert.equal(source.snapshot(scenario).positives, 0);
      if (["replacement", "truncate", "stall"].includes(scenario)) {
        assert.equal(source.snapshot(scenario).writes, 0);
      }
    }
    await waitFor(() => source.snapshot(scenario).active === 0);
    if (["replacement", "early_reject", "stall"].includes(scenario)) {
      await waitFor(() => source.snapshot(scenario).partialSocketCloses > 0);
    }
    results.push({ scenario, status: response.status, elapsedMilliseconds: Date.now() - started,
      source: source.snapshot(scenario) });
    console.log("CASE", JSON.stringify(results.at(-1)));
  }

  // Pinned workerd's HUP watcher does not reliably signal an ordinary client
  // FIN. This controlled case uses an explicit reset of the matched live socket;
  // it cannot qualify ordinary FIN propagation in the runtime's HTTP transport.
  let socket;
  const request = httpRequest({ hostname: "127.0.0.1", port: workerPort,
    path: "/_e2e/external-copy-stream", method: "POST",
    headers: { "content-type": "application/json" } });
  request.once("socket", value => { socket = value; });
  const pending = new Promise(resolve => {
    request.once("response", response => { response.resume(); resolve("unexpected response"); });
    request.once("error", error => resolve(error.code));
  });
  request.end(JSON.stringify({ scenario: "cancel" }));
  await waitFor(() => source.snapshot("cancel").reads === 1);
  assert(socket && !socket.destroyed, "Matched native request socket is live");
  socket.resetAndDestroy();
  assert(["ECONNRESET", "ERR_STREAM_DESTROYED"].includes(await pending));
  await waitFor(() => source.snapshot("cancel").active === 0);
  await waitFor(() => source.snapshot("cancel").partialSocketCloses > 0);
  results.push({ scenario: "cancel", inputTeardown: "matched live TCP reset",
    source: source.snapshot("cancel") });
  const resumed = await control("positive", AbortSignal.timeout(10000));
  const resumedBody = await resumed.text();
  assert.equal(resumed.status, 200, resumedBody);
  assert(JSON.parse(resumedBody).nativeSignalCloses >= 1, "Actual native request signal observed");
  assert.equal(source.snapshot("positive").positives, 2);
  results.push({ scenario: "capacity-after-cancel", status: resumed.status });
  await writeFile(join(root, "receipt.json"), JSON.stringify({ version: 1, workerd,
    files, results, scope: "Controlled real native transfer and cancellation; no production guard or provider acceptance" }, null, 2) + "\n",
  { flag: "wx", mode: 0o600 });
  console.log("PASS controlled copy bytes and cancellation", JSON.stringify(results));
} finally {
  await writeFile(join(root, "observations.json"), JSON.stringify({ results,
    final: Object.fromEntries(["positive", "replacement", "truncate", "wrong_second",
      "early_reject", "stall", "cancel"].map(value => [value, source.snapshot(value)])) }, null, 2) + "\n",
  { flag: "wx", mode: 0o600 });
  child.kill("SIGTERM");
  await terminal;
  await log.close();
  source.server.closeAllConnections();
  await new Promise(resolve => source.server.close(resolve));
}
