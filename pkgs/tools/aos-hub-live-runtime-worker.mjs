// Controlled adapter around the actual newly captured Rust Worker.
// Fixture diagnostics do not authenticate production ingress or publish data.

import { WorkerEntrypoint } from "cloudflare:workers";
import { fetch as rustFetch, HybridObjectGuard as RustGuard, getMemory } from "./shim.mjs";
import { mirrorFixtureEnv, MirrorFixtureStore } from "./provider.mjs";

export { MirrorFixtureStore };

export class HybridObjectGuard extends RustGuard {
  constructor(state, env) {
    super(state, mirrorFixtureEnv(env));
  }
}

export default class extends WorkerEntrypoint {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/__fixture/live-memory") {
      return Response.json({ wasmBytes: getMemory().buffer.byteLength });
    }
    if (path === "/__fixture/live-observations" && request.method === "GET") {
      return fetch("https://upstream.example.invalid/__fixture/live-observations");
    }
    return rustFetch(request, mirrorFixtureEnv(this.env), this.ctx);
  }
}
