// Test-only transparent faults around real Rust issuer/registry persistence.
// This copied subclass wrapper never enters the production artifact.

import Entrypoint, { HybridAuthorityIssuer as Issuer, HybridAuthorityState as Registry } from "./shim.mjs";

function wrappedState(state) {
  const storage = state.storage;
  const wrapped = new Proxy(storage, {
    get(target, name) {
      if (name === "transaction") return async (callback) => {
        const count = (await storage.get("fixture:transactions") ?? 0) + 1;
        await storage.put("fixture:transactions", count);
        let result;
        try {
          result = await target.transaction(callback);
        } catch (error) {
          console.error("fixture transaction rejected: " + String(error));
          throw error;
        }
        if (await storage.get("fixture:lost-ack") === count) {
          console.log("fixture lost acknowledgment after committed transaction " + count);
          throw new Error("fixture lost durable acknowledgment");
        }
        if (await storage.get("fixture:held-ack") === count) {
          await storage.put("fixture:held-entered", count);
          await new Promise(() => {
          });
        }
        return result;
      };
      const value = Reflect.get(target, name);
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
  return new Proxy(state, {
    get(target, name) {
      if (name === "storage") return wrapped;
      const value = Reflect.get(target, name);
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
}

async function fixture(storage, request) {
  const route = new URL(request.url).pathname;
  if (route === "/fixture-write") {
    for (const [key, value] of Object.entries(await request.json())) await storage.put(key, value);
    return new Response("ok");
  }
  if (route === "/fixture-read") {
    const keys = await request.json();
    return Response.json(Object.fromEntries(await Promise.all(keys.map(async (key) => [key, await storage.get(key)]))));
  }
  if (route === "/fixture-clear") {
    for (const key of await request.json()) await storage.delete(key);
    return new Response("ok");
  }
  if (route === "/fixture-reset") {
    await storage.deleteAll();
    return new Response("ok");
  }
  return null;
}

export class HybridAuthorityState extends Registry {
  constructor(state, env) {
    super(wrappedState(state), env);
    this.fixtureStorage = state.storage;
  }
  async fetch(request) {
    return await fixture(this.fixtureStorage, request) ?? super.fetch(request);
  }
}

export class HybridAuthorityIssuer extends Issuer {
  constructor(state, env) {
    super(wrappedState(state), env);
    this.fixtureStorage = state.storage;
  }
  async fetch(request) {
    const direct = await fixture(this.fixtureStorage, request);
    if (direct) return direct;
    const delta = await this.fixtureStorage.get("fixture:final-clock-delta-ms");
    if (delta === undefined) return super.fetch(request);
    const original = Date.now;
    let observations = 0;
    Date.now = () => original() + (++observations >= 6 ? delta : 0);
    try {
      return await super.fetch(request);
    } finally {
      Date.now = original;
      await this.fixtureStorage.put("fixture:clock-observations", observations);
    }
  }
}
export default Entrypoint;
