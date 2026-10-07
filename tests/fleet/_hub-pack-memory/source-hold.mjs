// A fixed TLS source fixture owns one pack and two small publisher responses.
// It sends actual retained bytes once; cancellation never claims provider drain.

import https from "node:https";
import http from "node:http";
import { constants } from "node:fs";
import { open, lstat, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { uptime } from "node:os";

const remaining = cutoff => cutoff - uptime() * 1000;
const same = (a, b) => ["dev", "ino", "size", "mtimeNs", "ctimeNs"].every(key => a[key] === b[key]);

async function selectedFile(reference, maximum) {
  if (!Number.isSafeInteger(reference.bytes) || reference.bytes <= 0 || reference.bytes > maximum
      || !/^[a-f0-9]{64}$/.test(reference.sha256)) throw new Error("source reference differs");
  const file = await open(reference.file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.getuid()) || before.nlink !== 1n
        || (before.mode & 0o077n) !== 0n || before.size !== BigInt(reference.bytes)) {
      throw new Error("source file custody differs");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(65536);
    let offset = 0;
    while (offset < reference.bytes) {
      const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, reference.bytes - offset), offset);
      if (!bytesRead) throw new Error("source file ended early");
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (hash.digest("hex") !== reference.sha256 || !same(before, await file.stat({ bigint: true }))) {
      throw new Error("source immutable bytes changed");
    }
    return { file, before, reference };
  } catch (error) {
    await file.close();
    throw error;
  }
}

export async function startOwnedSource(config) {
  if (config.version !== 1 || config.host !== "aos.andyl.org:4778" || config.port !== 4778
      || !/^[a-f0-9]{32}$/.test(config.runId) || remaining(config.cutoffUptimeMillis) <= 2000
      || remaining(config.cutoffUptimeMillis) > 120000) throw new Error("source selection differs");
  if (config.bootId !== (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim()) {
    throw new Error("selected source boot differs");
  }
  const root = await lstat(config.privateRoot);
  if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== process.getuid()
      || (root.mode & 0o077) || config.controlSocket !== `${config.privateRoot}/source.sock`) {
    throw new Error("source control root differs");
  }
  const rows = [];
  const files = new Map();
  const held = new Map();
  let retired = false;
  let packReleased = false;
  let metadataReleased = false;
  let requests = 0;
  let controls = 0;
  const sockets = new Set();
  let timer;
  let server;
  let control;
  const record = row => {
    if (rows.length >= 32) throw new Error("source observation overflow");
    rows.push({ ...row, atUptimeMillis: uptime() * 1000 });
  };

  const retire = () => {
    retired = true;
    clearTimeout(timer);
    for (const socket of sockets) socket.destroy();
    for (const owner of held.values()) owner.response.destroy();
    held.clear();
    server?.close();
    control?.close();
  };
  try {
    const roles = ["pack", "index", "metadata0", "metadata1"];
    if (Object.keys(config.files).sort().join() !== roles.slice().sort().join()) {
      throw new Error("closed source files differ");
    }
    for (const role of roles) {
      const reference = config.files[role];
      const prefix = `/fleet-mirror/${config.runId}/`;
      if (!reference.path.startsWith(prefix) || reference.path.includes("?")
          || reference.path.includes("..") || files.has(reference.path)) throw new Error("source path differs");
      files.set(reference.path, { role, ...(await selectedFile(reference,
        role === "pack" ? 8 * 1024 * 1024 : role === "index" ? 4 * 1024 * 1024 : 256 * 1024)) });
    }
    server = https.createServer({ key: await readFile(config.tlsKeyFile),
      cert: await readFile(config.tlsCertificateFile) }, (request, response) => {
      void (async () => {
        if (retired || remaining(config.cutoffUptimeMillis) <= 0 || ++requests > 4
            || request.method !== "GET" || request.headers.host !== config.host
            || request.url.includes("?")) throw new Error("source request differs");
        const source = files.get(request.url);
        if (!source || rows.some(row => row.event === "received" && row.role === source.role)) {
          throw new Error("source original absent or replayed");
        }
        const metadata = source.role.startsWith("metadata");
        const expectedRange = `bytes=0-${source.reference.bytes - 1}`;
        if (metadata ? request.headers.range !== expectedRange : request.headers.range !== undefined) {
          throw new Error("source range geometry differs");
        }
        const etag = `"${source.reference.sha256}"`;
        if (request.headers["if-match"] !== undefined && request.headers["if-match"] !== etag) {
          throw new Error("source conditional identity differs");
        }
        response.writeHead(metadata ? 206 : 200, {
          ...(metadata ? { "content-range": `bytes 0-${source.reference.bytes - 1}/${source.reference.bytes}` } : {}),
          "content-length": source.reference.bytes,
          "content-type": "application/octet-stream", etag, "cache-control": "no-store" });
        record({ event: "received", role: source.role, target: request.url,
          sha256: source.reference.sha256, bytes: source.reference.bytes,
          actualIfMatch: request.headers["if-match"] ?? null, providerVersion: null });
        const owner = { source, response, offset: 0 };
        if (source.role === "pack") {
          const prefix = Buffer.alloc(Math.min(65536, source.reference.bytes));
          const { bytesRead } = await source.file.read(prefix, 0, prefix.length, 0);
          if (bytesRead !== prefix.length) throw new Error("pack prefix ended early");
          if (remaining(config.cutoffUptimeMillis) <= 0) throw new Error("source cutoff reached");
          response.write(prefix);
          owner.offset = prefix.length;
          record({ event: "prefix_offered", role: "pack", bytes: prefix.length });
        }
        if (source.role === "index") await send(owner);
        else held.set(source.role, owner);
      })().catch(error => {
        response.destroy(error);
        retire();
      });
    });
    async function send(owner) {
      if (retired || remaining(config.cutoffUptimeMillis) <= 0
          || !same(owner.source.before, await owner.source.file.stat({ bigint: true }))) {
        throw new Error("source owner identity or cutoff changed");
      }
      const stream = owner.source.file.createReadStream({ start: owner.offset,
        end: owner.source.reference.bytes - 1, autoClose: false, highWaterMark: 65536 });
      await new Promise((resolve, reject) => {
        const fail = error => { stream.destroy(); reject(error); };
        owner.response.once("error", fail);
        owner.response.once("close", () => {
          if (!owner.response.writableFinished) fail(new Error("source response closed early"));
        });
        stream.once("error", fail);
        stream.once("end", () => {
          if (remaining(config.cutoffUptimeMillis) <= 0) owner.response.destroy();
        });
        owner.response.once("finish", resolve);
        stream.pipe(owner.response);
      });
      record({ event: "offered_finished", role: owner.source.role,
        bytes: owner.source.reference.bytes, providerConsumedBytes: null });
    }
    control = http.createServer((request, response) => {
      void (async () => {
        if (++controls > 512 || request.method !== "POST" || request.url !== "/control"
            || retired || remaining(config.cutoffUptimeMillis) <= 0) throw new Error("source control differs");
        let bytes = 0;
        const parts = [];
        for await (const chunk of request) {
          bytes += chunk.length;
          if (bytes > 256) throw new Error("source control exceeds bound");
          parts.push(chunk);
        }
        const command = JSON.parse(Buffer.concat(parts).toString());
        if (Object.keys(command).join() !== "action") throw new Error("source control schema differs");
        if (command.action === "release_metadata") {
          if (metadataReleased || !held.has("pack") || !held.has("metadata0") || !held.has("metadata1")) {
            throw new Error("source actual held owners absent");
          }
          metadataReleased = true;
          const owners = [held.get("metadata0"), held.get("metadata1")];
          held.delete("metadata0"); held.delete("metadata1");
          await Promise.all(owners.map(send));
        } else if (command.action === "release_pack") {
          if (packReleased || !metadataReleased || !held.has("pack")) throw new Error("source release order differs");
          packReleased = true;
          const owner = held.get("pack"); held.delete("pack");
          await send(owner);
        } else if (command.action !== "state" && command.action !== "retire") {
          throw new Error("source action differs");
        }
        const result = JSON.stringify({ version: 1, rows, held: [...held.keys()],
          packReleased, metadataReleased, retired, providerDrain: null });
        response.setHeader("content-length", Buffer.byteLength(result));
        if (command.action === "retire") response.once("finish", retire);
        response.end(result);
      })().catch(error => { response.destroy(error); retire(); });
    });
    for (const listener of [server, control]) listener.on("connection", socket => {
      sockets.add(socket); socket.once("close", () => sockets.delete(socket));
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject); server.listen(config.port, "0.0.0.0", resolve);
    });
    await new Promise((resolve, reject) => {
      control.once("error", reject); control.listen(config.controlSocket, resolve);
    });
    timer = setTimeout(retire, remaining(config.cutoffUptimeMillis));
    return { state: () => ({ rows: rows.slice(), retired, providerDrain: null }),
      stop: retire, closeFiles: async () => {
        retire(); await Promise.all([...files.values()].map(source => source.file.close()));
      } };
  } catch (error) {
    retire();
    await Promise.allSettled([...files.values()].map(source => source.file.close()));
    throw error;
  }
}
