// Controlled HTTPS source and UploadPart sink for the actual native copy pump.
// These socket observations confer no production provider acceptance.

import { createHash } from "node:crypto";
import { createServer } from "node:https";

export const sourceBytes = 5 * 1024 * 1024 + 7;
export const sourceSha256 = createHash("sha256")
  .update(Buffer.alloc(sourceBytes, 0x61)).digest("hex");

export function createCopySource({ cert, key }) {
  const observations = new Map();
  const snapshot = scenario => ({ ...observations.get(scenario) });
  const server = createServer({ cert, key }, async (request, response) => {
    const url = new URL(request.url, "https://copy-fixture.invalid");
    const [, prefix, scenario, operation] = url.pathname.split("/");
    if (prefix !== "fixture" || !scenario || !["source", "destination"].includes(operation)) {
      response.writeHead(404).end();
      return;
    }
    let state = observations.get(scenario);
    if (!state) {
      state = { reads: 0, writes: 0, positives: 0, active: 0, peak: 0,
        abandoned: 0, partialSocketCloses: 0, received: 0 };
      observations.set(scenario, state);
    }
    if (operation === "destination") {
      state.writes++;
      if (request.method !== "PUT" || url.searchParams.get("partNumber") !== "1"
          || url.searchParams.get("uploadId") !== "controlled-positive-upload"
          || request.headers["content-length"] !== String(sourceBytes)
          || request.headers["transfer-encoding"] !== undefined
          || request.headers["x-amz-checksum-sha256"] !== Buffer.from(sourceSha256, "hex").toString("base64")) {
        response.writeHead(400).end();
        return;
      }
      if (scenario === "early_reject") {
        response.writeHead(413).end();
        return;
      }
      const digest = createHash("sha256");
      let bytes = 0;
      try {
        for await (const chunk of request) {
          bytes += chunk.length;
          digest.update(chunk);
        }
      } catch {
        return;
      }
      state.received = bytes;
      if (bytes !== sourceBytes || digest.digest("hex") !== sourceSha256) {
        response.writeHead(400).end();
        return;
      }
      state.positives++;
      response.writeHead(200, { etag: '"controlled-part-tag"', "content-length": "0" }).end();
      return;
    }

    state.reads++;
    state.active++;
    state.peak = Math.max(state.peak, state.active);
    const readNumber = state.reads;
    let sent = 0;
    let ended = false;
    response.once("close", () => {
      state.active--;
      if (!ended) state.abandoned++;
    });
    request.socket.once("close", () => {
      if (sent < sourceBytes) state.partialSocketCloses++;
    });
    if (request.method !== "GET"
        || url.searchParams.getAll("versionId").join() !== "controlled-source-version"
        || request.headers["if-match"] !== '"controlled-source-tag"'
        || request.headers.range !== `bytes=0-${sourceBytes - 1}`) {
      response.writeHead(400).end();
      return;
    }
    response.writeHead(206, {
      etag: scenario === "replacement" ? '"changed-source-tag"' : '"controlled-source-tag"',
      "x-amz-version-id": "controlled-source-version",
      "content-length": String(sourceBytes),
      "content-range": `bytes 0-${sourceBytes - 1}/${sourceBytes}`,
    });
    response.flushHeaders();
    if (scenario === "replacement") return;

    const chunk = Buffer.alloc(16 * 1024,
      scenario === "wrong_second" && readNumber === 2 ? 0x62 : 0x61);
    while (!response.destroyed && sent < sourceBytes) {
      const bytes = Math.min(chunk.length, sourceBytes - sent);
      sent += bytes;
      if (!response.write(chunk.subarray(0, bytes))) {
        const writable = await new Promise(resolve => {
          const ready = () => { cleanup(); resolve(true); };
          const closed = () => { cleanup(); resolve(false); };
          const cleanup = () => {
            response.off("drain", ready);
            response.off("close", closed);
          };
          response.once("drain", ready);
          response.once("close", closed);
        });
        if (!writable) return;
      }
      if (["stall", "cancel"].includes(scenario)) return;
      if (scenario === "truncate") { response.destroy(); return; }
      if (scenario === "early_reject" && readNumber === 2) {
        await new Promise(resolve => setTimeout(resolve, 5));
      }
    }
    if (!response.destroyed && sent === sourceBytes) {
      ended = true;
      response.end();
    }
  });
  return { server, snapshot };
}
