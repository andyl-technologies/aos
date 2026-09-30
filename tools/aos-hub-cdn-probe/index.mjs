// A static CDN needs a nonce responder at its TLS edge. Only this well-known
// path runs through a Worker; registry objects continue directly to R2.

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decodeBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function unavailable() {
  return new Response("Probe unavailable", { status: 404 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const nonce = url.searchParams.get("nonce");
    const generation = Number(env.PROBE_ENDPOINT_GENERATION);

    if (
      request.method !== "GET" ||
      url.protocol !== "https:" ||
      url.hostname !== env.PROBE_HOSTNAME ||
      url.pathname !== "/.well-known/aos-domain-probe" ||
      !/^[A-Za-z0-9_-]{43}$/.test(nonce ?? "") ||
      !Number.isSafeInteger(generation) ||
      generation <= 0
    ) {
      return unavailable();
    }

    const nonceBytes = decodeBase64(nonce.replaceAll("-", "+").replaceAll("_", "/") + "=");
    if (nonceBytes.length !== 32 || base64url(nonceBytes) !== nonce) {
      return unavailable();
    }

    const guard = env.PROBE_CHALLENGES.get(
      env.PROBE_CHALLENGES.idFromName(env.PROBE_ENDPOINT_ID),
    );
    const consumed = await guard.fetch("https://challenge/consume", {
      method: "POST",
      body: nonce,
    });
    if (!consumed.ok) {
      return unavailable();
    }

    const key = await crypto.subtle.importKey(
      "pkcs8",
      decodeBase64(env.PROBE_SIGNING_PKCS8),
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const now = Math.floor(Date.now() / 1000);
    // Field order matches the Hub's canonical version-two TLS statement.
    const statement = {
      version: 2,
      issued_at: now,
      expires_at: now + 30,
      nonce,
      hostname: env.PROBE_HOSTNAME,
      endpoint_id: env.PROBE_ENDPOINT_ID,
      endpoint_generation: generation,
      responder_key_identity_sha256: env.PROBE_PUBLIC_KEY_SHA256,
    };
    const payload = new TextEncoder().encode(JSON.stringify(statement));
    const signature = await crypto.subtle.sign("Ed25519", key, payload);

    return Response.json(
      { payload: base64url(payload), signature: base64url(signature) },
      { headers: { "Cache-Control": "no-store" } },
    );
  },
};

// Serialize consumption so concurrent requests cannot reuse a challenge.
// Retain challenges past their signed lifetime and remove them by alarm.
export class ProbeChallengeGuard {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const nonce = await request.text();
    if (request.method !== "POST" || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
      return new Response(null, { status: 400 });
    }

    const now = Date.now();
    const consumed = await this.state.storage.transaction(async (storage) => {
      if (await storage.get(nonce)) {
        return false;
      }
      await storage.put(nonce, now + 60_000);
      return true;
    });
    if (!(await this.state.storage.getAlarm())) {
      await this.state.storage.setAlarm(now + 60_000);
    }
    return new Response(null, { status: consumed ? 204 : 409 });
  }

  async alarm() {
    const now = Date.now();
    const challenges = await this.state.storage.list();
    const expired = [...challenges].filter(([, expires]) => expires <= now);
    if (expired.length > 0) {
      await this.state.storage.delete(expired.map(([nonce]) => nonce));
    }
    if (challenges.size > expired.length) {
      await this.state.storage.setAlarm(now + 60_000);
    }
  }
}
