// Controlled wrapper for the actual compiled Rust Worker and physical guard.
// These imports are copied into the runner alongside the immutable artifact.

import { WorkerEntrypoint } from "cloudflare:workers";
import { fetch as rustFetch, HybridObjectGuard as RustGuard, getMemory } from "./shim.mjs";
import { mirrorFixtureEnv, MirrorFixtureStore } from "./provider.mjs";
import { guardState } from "./guard-state.mjs";

export { MirrorFixtureStore };

export class HybridObjectGuard extends RustGuard {
  constructor(state, env) {
    super(state, mirrorFixtureEnv(env));
    this.fixtureState = state;
    this.pageDelayMilliseconds = 0;
    const storage = state.storage;
    const get = storage.get.bind(storage);
    storage.get = async (...args) => {
      if (this.pageDelayMilliseconds && typeof args[0] === "string" && args[0].startsWith("membership-page-")) {
        const delay = this.pageDelayMilliseconds;
        this.pageDelayMilliseconds = 0;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      return get(...args);
    };
  }

  async fetch(request) {
    if (new URL(request.url).pathname === "/__fixture/guard-state") {
      const { claimId } = await request.json();
      return Response.json(await guardState(this.fixtureState.storage, claimId));
    }
    if (new URL(request.url).pathname === "/__fixture/cache") {
      const { action } = await request.json();
      const storage = this.fixtureState.storage;
      const header = await storage.get("membership-cache-header");
      if (!header) return new Response(null, { status: 404 });
      if (action === "expire") {
        header.createdAt = Math.floor(Date.now() / 1000) - 601;
        header.expiresAt = header.createdAt + 600;
        await storage.put("membership-cache-header", header);
      } else if (action === "remove-page") {
        await storage.delete("membership-page-000");
      } else if (action === "remove-header") {
        await storage.delete("membership-cache-header");
      } else if (action === "substitute-source") {
        header.pair.index.etag = '"substituted-source"';
        await storage.put("membership-cache-header", header);
      } else if (action === "delay-page") {
        this.pageDelayMilliseconds = 6000;
      } else {
        return new Response(null, { status: 400 });
      }
      return new Response(null, { status: 204 });
    }
    return super.fetch(request);
  }
}

export default class extends WorkerEntrypoint {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/__fixture/memory") {
      return Response.json({ wasmBytes: getMemory().buffer.byteLength });
    }
    if (path === "/__fixture/guard-state" && request.method === "POST") {
      const input = await request.clone().json();
      if (typeof input.key !== "string"
          || !/^\.aos-mirror-qualification\/[a-f0-9]{32}\/final\/[a-zA-Z0-9_.\/-]+$/.test(input.key)
          || input.key.split("/").some(part => ["", ".", ".."].includes(part))
          || typeof input.claimId !== "string"
          || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(input.claimId)) {
        return new Response(null, { status: 400 });
      }
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input.key))))
        .map(byte => byte.toString(16).padStart(2, "0")).join("");
      const namespace = this.env.HYBRID_OBJECT_GUARD;
      const guard = namespace.get(namespace.idFromName(`${this.env.HUB_DEPLOYMENT_ID}:${digest}`));
      return guard.fetch("https://fixture/__fixture/guard-state", request);
    }
    if (path === "/__fixture/cache" && request.method === "POST") {
      const input = await request.clone().json();
      if (typeof input.key !== "string" || !/^\.aos-mirror-query\/[a-f0-9]{64}$/.test(input.key)) {
        return new Response(null, { status: 400 });
      }
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input.key))))
        .map(byte => byte.toString(16).padStart(2, "0")).join("");
      const namespace = this.env.HYBRID_OBJECT_GUARD;
      const guard = namespace.get(namespace.idFromName(`${this.env.HUB_DEPLOYMENT_ID}:${digest}`));
      return guard.fetch("https://fixture/__fixture/cache", request);
    }
    if (path === "/__fixture/upstream-observations") {
      return fetch("https://upstream.example.invalid/__fixture/observations");
    }
    if (path.startsWith("/__fixture/upstream/")) {
      return fetch(`https://upstream.example.invalid/registry/${path.slice("/__fixture/upstream/".length)}`);
    }
    if (path.startsWith("/__fixture/provider/")) {
      const namespace = this.env.MIRROR_FIXTURE_STORE;
      const store = namespace.get(namespace.idFromName("mirror-controlled-provider"));
      const action = path.slice("/__fixture/provider/".length);
      return store.fetch(`https://fixture/${action}`, request);
    }

    return rustFetch(request, mirrorFixtureEnv(this.env), this.ctx);
  }
}
