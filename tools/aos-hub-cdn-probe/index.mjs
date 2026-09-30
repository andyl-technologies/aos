// Only the well-known proof path uses this Worker. Artifact objects remain on R2.

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function unavailable() {
  return new Response("Probe unavailable", { status: 404 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const generation = Number(env.PROBE_ENDPOINT_GENERATION);
    if (
      request.method !== "GET" ||
      url.protocol !== "https:" ||
      url.hostname !== env.PROBE_HOSTNAME ||
      url.pathname !== "/.well-known/aos-domain-probe" ||
      !Number.isSafeInteger(generation) ||
      generation <= 0
    ) {
      return unavailable();
    }

    const guard = env.PROBE_CHALLENGES.get(
      env.PROBE_CHALLENGES.idFromName(env.PROBE_ENDPOINT_ID),
    );
    if (url.searchParams.get("public_key") === "1") {
      return guard.fetch("https://challenge/public-key");
    }

    const nonce = url.searchParams.get("nonce");
    if (!/^[A-Za-z0-9_-]{43}$/.test(nonce ?? "")) {
      return unavailable();
    }
    const bytes = Uint8Array.from(
      atob(nonce.replaceAll("-", "+").replaceAll("_", "/") + "="),
      (character) => character.charCodeAt(0),
    );
    if (bytes.length !== 32 || base64url(bytes) !== nonce) {
      return unavailable();
    }
    return guard.fetch("https://challenge/sign", { method: "POST", body: nonce });
  },
};

// The key is generated in provider storage and never leaves this object.
// Challenge consumption is serialized and retained past the proof lifetime.
export class ProbeChallengeGuard {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.ready = state.blockConcurrencyWhile(async () => {
      let identity = await state.storage.get("identity");
      if (!identity) {
        const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
        identity = {
          privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
          publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
        };
        await state.storage.put("identity", identity);
      }
      this.publicKey = identity.publicKey;
      this.key = await crypto.subtle.importKey("pkcs8", identity.privateKey, "Ed25519", false, ["sign"]);
      const digest = await crypto.subtle.digest("SHA-256", identity.publicKey);
      this.publicKeyHash = [...new Uint8Array(digest)]
        .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    });
  }

  async fetch(request) {
    await this.ready;
    if (new URL(request.url).pathname === "/public-key") {
      return Response.json({ publicKey: base64url(this.publicKey) }, {
        headers: { "Cache-Control": "no-store" },
      });
    }

    const nonce = await request.text();
    if (request.method !== "POST" || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
      return unavailable();
    }
    const now = Date.now();
    const consumed = await this.state.storage.transaction(async (storage) => {
      const name = "challenge:" + nonce;
      if (await storage.get(name)) {
        return false;
      }
      await storage.put(name, now + 60_000);
      return true;
    });
    if (!consumed) {
      return unavailable();
    }
    if (!(await this.state.storage.getAlarm())) {
      await this.state.storage.setAlarm(now + 60_000);
    }

    // Field order matches the Hub's canonical version-two TLS statement.
    const issued = Math.floor(now / 1000);
    const payload = new TextEncoder().encode(JSON.stringify({
      version: 2,
      issued_at: issued,
      expires_at: issued + 30,
      nonce,
      hostname: this.env.PROBE_HOSTNAME,
      endpoint_id: this.env.PROBE_ENDPOINT_ID,
      endpoint_generation: Number(this.env.PROBE_ENDPOINT_GENERATION),
      responder_key_identity_sha256: this.publicKeyHash,
    }));
    const signature = await crypto.subtle.sign("Ed25519", this.key, payload);
    return Response.json({ payload: base64url(payload), signature: base64url(signature) }, {
      headers: { "Cache-Control": "no-store" },
    });
  }

  async alarm() {
    const now = Date.now();
    const challenges = await this.state.storage.list({ prefix: "challenge:" });
    const expired = [...challenges].filter(([, expires]) => expires <= now);
    if (expired.length > 0) {
      await this.state.storage.delete(expired.map(([nonce]) => nonce));
    }
    if (challenges.size > expired.length) {
      await this.state.storage.setAlarm(now + 60_000);
    }
  }
}
