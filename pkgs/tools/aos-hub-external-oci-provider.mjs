// Confined in-memory version history for the controlled OCI TLS provider.
// The caller authenticates SigV4 before exposing these operations. Every version
// identifies bytes actually stored by a PUT or completed multipart upload.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export class VersionedObjects {
  #versions = new Map();
  #sequence = 0;
  #retainedBytes = 0;
  #retainedVersions = 0;
  #prefix;

  constructor(prefix) {
    assert(prefix.length > 0 && !prefix.endsWith("/"));
    this.#prefix = prefix;
  }

  #admitted(key) {
    return key.startsWith(`${this.#prefix}/oci/`)
      || key.startsWith(`${this.#prefix}/.aos-internal/conditional-delete-probes/`);
  }

  put(key, bytes) {
    assert(this.#admitted(key), "Provider write leaves the confined fixture namespace");
    assert(Buffer.isBuffer(bytes) && bytes.length <= 20 * 1024 * 1024);
    assert(this.#retainedVersions < 128 && this.#retainedBytes + bytes.length <= 64 * 1024 * 1024,
      "Controlled provider history exceeds its explicit retention budget");
    const retained = Buffer.from(bytes);
    this.#retainedBytes += retained.length;
    this.#retainedVersions++;
    const object = Object.freeze({ bytes: retained,
      version: `stored-version-${++this.#sequence}`,
      etag: `"${createHash("sha256").update(retained).digest("hex")}"` });
    const versions = this.#versions.get(key) ?? new Map();
    versions.set(object.version, object);
    this.#versions.set(key, versions);
    return object;
  }

  get(key, version) {
    const versions = this.#versions.get(key);
    if (!versions) return undefined;
    return version ? versions.get(version) : [...versions.values()].at(-1);
  }

  keys() {
    return [...this.#versions.keys()];
  }

  conditionalDelete(key, version, etag) {
    assert(this.#admitted(key), "Provider delete leaves the confined fixture namespace");
    if (!version || !etag || !/^"[^"\r\n]+"$/.test(etag)) {
      return { status: 403, deleted: false };
    }
    const versions = this.#versions.get(key);
    const object = versions?.get(version);
    if (!object) return { status: versions ? 412 : 404, deleted: false };
    if (object.etag !== etag) return { status: 412, deleted: false };
    versions.delete(version);
    this.#retainedBytes -= object.bytes.length;
    this.#retainedVersions--;
    if (versions.size === 0) this.#versions.delete(key);
    return { status: 204, deleted: true, object };
  }
}
