// SQLite-backed ordinary R2 JS binding surface for controlled mirror tests.
//
// This provider belongs only to the source-built workerd runner. It measures
// the real Rust producer's streams, SDK promises and durable effect journal;
// it supplies no evidence about hosted Cloudflare R2 or production acceptance.

const PART_BYTES = 8 * 1024 * 1024;
const CHUNK_BYTES = 64 * 1024;
const PRIVATE = ".aos-direct-upload/mirror/";
const FINAL = ".aos-mirror-qualification/";

function requireKey(key) {
  if (typeof key !== "string" || key.length > 4096
      || (!key.startsWith(PRIVATE) && !key.startsWith(FINAL))) {
    throw new Error("fixture provider refuses a nonreserved key");
  }
}

function id() {
  return crypto.randomUUID().replaceAll("-", "");
}

function etag() {
  return `"${id()}"`;
}

async function checked(response) {
  if (!response.ok) {
    // A failed promise remains a genuine unknown in the producer. Never turn
    // the provider's retained state into a fabricated successful SDK receipt.
    throw new Error(`controlled provider request failed (${response.status})`);
  }
  return response;
}

// worker-rs checks the binding constructor name before calling its ordinary
// JS methods. This controlled adapter supplies that interface identity; every
// method below still reaches the retained SQLite provider and actual streams.
class R2Bucket {}

function bucket(namespace) {
  const store = namespace.get(namespace.idFromName("mirror-controlled-provider"));
  async function request(action, key, fields = {}, body) {
    requireKey(key);
    const headers = { "x-aos-fixture-key": key, "x-aos-fixture-fields": JSON.stringify(fields) };
    return checked(await store.fetch(`https://mirror-provider/${action}`, {
      method: "POST", headers, body,
    }));
  }

  function multipart(key, uploadId) {
    return {
      key,
      uploadId,
      async uploadPart(partNumber, bytes) {
        return (await request("part", key, { uploadId, partNumber }, bytes)).json();
      },
      async complete(parts) {
        return (await request("complete", key, { uploadId, parts })).json();
      },
      async abort() {
        await request("abort", key, { uploadId });
      },
    };
  }

  return Object.assign(new R2Bucket(), {
    async createMultipartUpload(key) {
      const created = await (await request("create", key)).json();
      return multipart(key, created.uploadId);
    },
    resumeMultipartUpload(key, uploadId) {
      requireKey(key);
      return multipart(key, uploadId);
    },
    async put(key, bytes) {
      return (await request("empty", key, {}, bytes)).json();
    },
    async head(key) {
      const response = await request("head", key);
      return response.status === 204 ? null : response.json();
    },
    async get(key, options = {}) {
      const response = await request("get", key, { range: options.range });
      if (response.status === 204) return null;
      return { ...JSON.parse(response.headers.get("x-aos-fixture-object")), body: response.body };
    },
    async delete(key) {
      await request("delete", key);
    },
  });
}

/** Injects the controlled provider into both ordinary Worker and DO inputs. */
export function mirrorFixtureEnv(env) {
  return { ...env, REGISTRY_BUCKET: bucket(env.MIRROR_FIXTURE_STORE) };
}

/** Retains actual provider bytes, incarnations and request facts in DO SQLite. */
export class MirrorFixtureStore {
  constructor(state) {
    this.state = state;
    this.sql = state.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS mirror_fixture_uploads (
        upload_id TEXT PRIMARY KEY, object_key TEXT NOT NULL, state TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS mirror_fixture_parts (
        upload_id TEXT NOT NULL, part_number INTEGER NOT NULL, byte_size INTEGER NOT NULL,
        etag TEXT NOT NULL, PRIMARY KEY(upload_id, part_number)
      );
      CREATE TABLE IF NOT EXISTS mirror_fixture_chunks (
        upload_id TEXT NOT NULL, part_number INTEGER NOT NULL, chunk_number INTEGER NOT NULL,
        byte_start INTEGER NOT NULL, bytes BLOB NOT NULL,
        PRIMARY KEY(upload_id, part_number, chunk_number)
      );
      CREATE TABLE IF NOT EXISTS mirror_fixture_objects (
        object_key TEXT PRIMARY KEY, upload_id TEXT NOT NULL, byte_size INTEGER NOT NULL,
        etag TEXT NOT NULL, version TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS mirror_fixture_requests (
        ordinal INTEGER PRIMARY KEY, action TEXT NOT NULL, input_bytes INTEGER NOT NULL,
        output_bytes INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS mirror_fixture_faults (
        action TEXT PRIMARY KEY, remaining INTEGER NOT NULL
      );
    `);
  }

  row(query, ...args) {
    return this.sql.exec(query, ...args).toArray()[0];
  }

  object(key) {
    const row = this.row("SELECT * FROM mirror_fixture_objects WHERE object_key = ?", key);
    return row && { key, size: row.byte_size, etag: row.etag, httpEtag: row.etag, version: row.version };
  }

  heldUpload(key, uploadId) {
    const upload = this.row("SELECT * FROM mirror_fixture_uploads WHERE upload_id = ?", uploadId);
    if (!upload || upload.object_key !== key || upload.state !== "open") {
      throw new Error("fixture multipart identity is closed or changed");
    }
    return upload;
  }

  faultAfterPositive(action) {
    const fault = this.row("SELECT remaining FROM mirror_fixture_faults WHERE action = ?", action);
    if (fault?.remaining > 0) {
      this.sql.exec("UPDATE mirror_fixture_faults SET remaining = remaining - 1 WHERE action = ?", action);
      return true;
    }
    return false;
  }

  async fetch(request) {
    const action = new URL(request.url).pathname.slice(1);
    if (action === "observations") {
      return Response.json({
        operations: this.sql.exec(`SELECT action, count(*) AS requests, sum(input_bytes) AS input_bytes,
          sum(output_bytes) AS output_bytes FROM mirror_fixture_requests GROUP BY action ORDER BY action`).toArray(),
        objects: this.sql.exec("SELECT object_key, byte_size, version FROM mirror_fixture_objects ORDER BY object_key").toArray(),
        openUploads: this.row("SELECT count(*) AS count FROM mirror_fixture_uploads WHERE state = 'open'").count,
      });
    }
    if (action === "fault") {
      const { action: target, remaining } = await request.json();
      if (!["create", "complete", "delete", "abort"].includes(target) || remaining !== 1) {
        return new Response("invalid bounded fault", { status: 400 });
      }
      this.sql.exec("INSERT OR REPLACE INTO mirror_fixture_faults VALUES (?, ?)", target, remaining);
      return new Response(null, { status: 204 });
    }

    const key = request.headers.get("x-aos-fixture-key");
    requireKey(key);
    const fields = JSON.parse(request.headers.get("x-aos-fixture-fields") ?? "{}");
    try {
      return await this.execute(action, key, fields, request);
    } catch {
      return new Response("controlled provider operation refused", { status: 409 });
    }
  }

  async execute(action, key, fields, request) {
    this.sql.exec("INSERT INTO mirror_fixture_requests(action, input_bytes) VALUES (?, 0)", action);
    const ordinal = this.row("SELECT last_insert_rowid() AS ordinal").ordinal;
    if (action === "create") {
      const uploadId = id();
      this.sql.exec("INSERT INTO mirror_fixture_uploads VALUES (?, ?, 'open')", uploadId, key);
      return this.faultAfterPositive(action)
        ? new Response("positive create reply lost", { status: 502 })
        : Response.json({ uploadId });
    }
    if (action === "part") {
      this.heldUpload(key, fields.uploadId);
      if (!Number.isInteger(fields.partNumber) || fields.partNumber < 1 || fields.partNumber > 256) {
        throw new Error("fixture part geometry is invalid");
      }
      if (this.row("SELECT 1 FROM mirror_fixture_parts WHERE upload_id = ? AND part_number = ?", fields.uploadId, fields.partNumber)) {
        throw new Error("fixture part already has a positive identity");
      }
      let size = 0;
      let chunkNumber = 0;
      const reader = request.body.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          for (let offset = 0; offset < value.length; offset += CHUNK_BYTES) {
            const chunk = value.slice(offset, offset + CHUNK_BYTES);
            if (size + chunk.length > PART_BYTES) throw new Error("fixture part exceeds bound");
            this.sql.exec("INSERT INTO mirror_fixture_chunks VALUES (?, ?, ?, ?, ?)",
              fields.uploadId, fields.partNumber, chunkNumber++, (fields.partNumber - 1) * PART_BYTES + size, chunk);
            size += chunk.length;
          }
        }
      } finally {
        reader.releaseLock();
      }
      // Multipart SDK receipts use the unquoted entity tag. Object HTTP ETags
      // remain quoted; the Rust producer retains their canonical strong form.
      const partEtag = etag().slice(1, -1);
      this.sql.exec("INSERT INTO mirror_fixture_parts VALUES (?, ?, ?, ?)", fields.uploadId, fields.partNumber, size, partEtag);
      this.sql.exec("UPDATE mirror_fixture_requests SET input_bytes = ? WHERE ordinal = ?", size, ordinal);
      return Response.json({ etag: partEtag });
    }
    if (action === "complete") {
      this.heldUpload(key, fields.uploadId);
      const actual = this.sql.exec("SELECT * FROM mirror_fixture_parts WHERE upload_id = ? ORDER BY part_number", fields.uploadId).toArray();
      if (!Array.isArray(fields.parts) || actual.length !== fields.parts.length || actual.length === 0
          || actual.some((part, index) => part.part_number !== index + 1
            || fields.parts[index].partNumber !== part.part_number || fields.parts[index].etag !== part.etag
            || (index + 1 < actual.length && part.byte_size !== PART_BYTES))) {
        throw new Error("fixture completion changed the acknowledged manifest");
      }
      const size = actual.reduce((sum, part) => sum + part.byte_size, 0);
      this.state.storage.transactionSync(() => {
        this.sql.exec("UPDATE mirror_fixture_uploads SET state = 'complete' WHERE upload_id = ?", fields.uploadId);
        this.sql.exec("INSERT OR REPLACE INTO mirror_fixture_objects VALUES (?, ?, ?, ?, ?)", key, fields.uploadId, size, etag(), id());
      });
      return this.faultAfterPositive(action)
        ? new Response("positive complete reply lost", { status: 502 })
        : Response.json(this.object(key));
    }
    if (action === "empty") {
      const bytes = await request.arrayBuffer();
      if (bytes.byteLength !== 0) throw new Error("fixture put is empty-only");
      this.sql.exec("INSERT OR REPLACE INTO mirror_fixture_objects VALUES (?, ?, 0, ?, ?)", key, id(), etag(), id());
      return Response.json(this.object(key));
    }
    if (action === "abort") {
      this.heldUpload(key, fields.uploadId);
      this.sql.exec("UPDATE mirror_fixture_uploads SET state = 'aborted' WHERE upload_id = ?", fields.uploadId);
      return this.faultAfterPositive(action)
        ? new Response("positive abort reply lost", { status: 502 }) : new Response(null, { status: 204 });
    }
    if (action === "delete") {
      this.sql.exec("DELETE FROM mirror_fixture_objects WHERE object_key = ?", key);
      return this.faultAfterPositive(action)
        ? new Response("positive delete reply lost", { status: 502 }) : new Response(null, { status: 204 });
    }
    if (action === "head") return this.object(key) ? Response.json(this.object(key)) : new Response(null, { status: 204 });
    if (action === "get") {
      const object = this.object(key);
      if (!object) return new Response(null, { status: 204 });
      const stored = this.row("SELECT upload_id FROM mirror_fixture_objects WHERE object_key = ?", key);
      let position = fields.range?.offset ?? 0;
      const end = position + (fields.range?.length ?? object.size);
      if (!Number.isSafeInteger(position) || position < 0 || !Number.isSafeInteger(end) || end > object.size) {
        throw new Error("fixture range is invalid");
      }
      const sql = this.sql;
      const body = new ReadableStream({
        type: "bytes",
        pull(controller) {
          if (position === end) {
            const pending = controller.byobRequest;
            controller.close();
            pending?.respond(0);
            return;
          }
          const part = Math.floor(position / PART_BYTES) + 1;
          const chunk = sql.exec(`SELECT byte_start, bytes FROM mirror_fixture_chunks
            WHERE upload_id = ? AND part_number = ? AND byte_start <= ?
              AND byte_start + length(bytes) > ? ORDER BY chunk_number LIMIT 1`,
          stored.upload_id, part, position, position).toArray()[0];
          if (!chunk) { controller.error(new Error("fixture incarnation lost a retained chunk")); return; }
          const all = new Uint8Array(chunk.bytes);
          const offset = position - chunk.byte_start;
          const selected = all.slice(offset, offset + Math.min(all.length - offset, end - position));
          position += selected.length;
          sql.exec("UPDATE mirror_fixture_requests SET output_bytes = output_bytes + ? WHERE ordinal = ?", selected.length, ordinal);
          controller.enqueue(selected);
        },
      });
      return new Response(body, { headers: { "x-aos-fixture-object": JSON.stringify(object) } });
    }
    throw new Error("fixture operation is not admitted");
  }
}
