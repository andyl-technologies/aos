// Controlled loopback mechanics only: no Worker, admission or provider claim.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir, uptime } from "node:os";
import path from "node:path";
import test from "node:test";
import { startOwnedSource } from "./source-hold.mjs";

const fixtures = path.resolve(import.meta.dirname, "../../fixtures");
const tls = {
  tlsKeyFile: path.join(fixtures, "hub-hybrid-fleet-server.key"),
  tlsCertificateFile: path.join(fixtures, "hub-hybrid-fleet-server.crt"),
};
const ca = await readFile(path.join(fixtures, "hub-hybrid-fleet-ca.crt"));

async function setup(bytes, span = 4000) {
  const root = await mkdtemp(path.join(tmpdir(), "aos-pack-source-test-"));
  const runId = "a".repeat(32);
  const files = {};
  for (const [role, body] of Object.entries({ pack: Buffer.alloc(bytes, 7),
    index: Buffer.from("controlled-index"), metadata0: Buffer.from("publisher-a"),
    metadata1: Buffer.from("publisher-b") })) {
    const file = path.join(root, role);
    await writeFile(file, body, { flag: "wx", mode: 0o600 });
    files[role] = { file, bytes: body.length, sha256: createHash("sha256").update(body).digest("hex"),
      path: `/fleet-mirror/${runId}/releases/memory/${runId}/live36/${role}` };
  }
  const selected = { version: 1, host: "aos.fleet.test:4778", port: 4778,
    frontedBySelectedMirror: true, runId, privateRoot: root, controlSocket: `${root}/source.sock`,
    bootId: (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim(),
    cutoffUptimeMillis: uptime() * 1000 + span, files, ...tls };
  let owner;
  try {
    owner = await startOwnedSource(selected);
  } catch (error) {
    await rm(root, { recursive: true });
    throw error;
  }
  return { selected, owner, root, async close() {
    await owner.closeFiles();
    await rm(root, { recursive: true });
  } };
}

function control(selected, action) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify({ action }));
    const request = http.request({ socketPath: selected.controlSocket, path: "/control", method: "POST",
      headers: { Host: "localhost", "Content-Length": body.length }, timeout: 1000 }, response => {
      const parts = [];
      response.on("data", chunk => parts.push(chunk));
      response.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(parts))); } catch (error) { reject(error); }
      });
      response.on("error", reject);
    });
    request.on("timeout", () => request.destroy(new Error("controlled control cutoff")));
    request.on("error", reject);
    request.end(body);
  });
}

function fetch(selected, role, rangeOverride = undefined) {
  return new Promise((resolve, reject) => {
    const row = selected.files[role];
    const headers = { Host: selected.host };
    if (role.startsWith("metadata")) headers.Range = `bytes=0-${row.bytes - 1}`;
    if (rangeOverride !== undefined) headers.Range = rangeOverride;
    const request = https.get({ hostname: "127.0.0.1", port: 4780, servername: "aos.fleet.test",
      path: row.path, headers, ca, agent: false, timeout: 4500 }, response => {
      const parts = [];
      response.on("data", chunk => parts.push(chunk));
      response.on("end", () => resolve({ bytes: Buffer.concat(parts), status: response.statusCode,
        etag: response.headers.etag }));
      response.on("error", reject);
      response.on("aborted", () => reject(new Error("controlled original aborted")));
    });
    request.on("timeout", () => request.destroy(new Error("controlled original cutoff")));
    request.on("error", reject);
  });
}

async function held(selected, expected) {
  const cutoff = uptime() * 1000 + 1000;
  while (uptime() * 1000 < cutoff) {
    const actual = await control(selected, "state");
    if (expected.every(role => actual.held.includes(role))) return actual;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error("controlled held-original receipt missing");
}

async function positive(bytes) {
  const actual = await setup(bytes);
  const originals = [];
  try {
    assert.equal((await fetch(actual.selected, "index")).status, 200);
    let packFinished = false;
    const pack = fetch(actual.selected, "pack").then(value => { packFinished = true; return value; });
    originals.push(pack);
    void pack.catch(() => {});
    const first = await held(actual.selected, ["pack"]);
    assert.equal(packFinished, false);
    assert.equal(first.rows.find(row => row.event === "prefix_offered").bytes, Math.min(65536, bytes - 1));
    const metadata = [fetch(actual.selected, "metadata0"), fetch(actual.selected, "metadata1")];
    originals.push(...metadata);
    for (const original of metadata) void original.catch(() => {});
    await held(actual.selected, ["pack", "metadata0", "metadata1"]);
    await control(actual.selected, "release_metadata");
    const finished = await Promise.all(metadata);
    assert.deepEqual(finished.map(row => row.status), [206, 206]);
    assert.equal(packFinished, false);
    await control(actual.selected, "release_pack");
    const returned = await pack;
    assert.equal(returned.bytes.length, bytes);
    assert.equal(createHash("sha256").update(returned.bytes).digest("hex"), actual.selected.files.pack.sha256);
    assert.equal(returned.etag, `"${actual.selected.files.pack.sha256}"`);
    const state = await control(actual.selected, "state");
    assert.equal(state.providerDrain, null);
    assert.equal(state.rows.filter(row => row.event === "received").length, 4);
    await control(actual.selected, "retire");
  } finally {
    await actual.close();
    await Promise.allSettled(originals);
  }
}

test("fronted tiny pack holds original EOF and resumes the same source", { timeout: 6000 }, () => positive(256));
test("fronted larger pack resumes after its actual held prefix", { timeout: 6000 }, () => positive(256 * 1024));

test("wrong metadata range refuses instead of adopting a replacement", { timeout: 6000 }, async () => {
  const actual = await setup(256);
  try {
    await assert.rejects(fetch(actual.selected, "metadata0", "bytes=1-2"));
    assert.equal(actual.owner.state().retired, true);
    assert.equal(actual.owner.state().providerDrain, null);
  } finally {
    await actual.close();
  }
});
