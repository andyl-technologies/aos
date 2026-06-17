##! aos-registry-worker-e2e — launcher that runs the deployed Worker e2e.
##!
##! `cargo test --workspace` exercises the shared handler logic on the **native**
##! target; it never runs the wasm artifact on a Cloudflare-like runtime, so it
##! cannot catch wasm-only runtime faults (a `wasm32-unknown-unknown` panic, a
##! binding-shape mismatch, the bridge's async behavior under workerd). This
##! check closes that gap: it boots the real `aos-registry-worker-dist` build
##! (`shim.mjs` + `index.wasm`) under miniflare 3 driving the **from-source**
##! `pkgs.workerd` (the npm workerd is a prebuilt ELF blob that does not run on
##! NixOS; miniflare honors `MINIFLARE_WORKERD_PATH`), with D1/R2/KV bindings, and
##! asserts the live request surface responds:
##!
##! ```text
##! GET  /_init                                          -> 200 "schema applied"
##! POST /aos.registry.v1.RegistryService/ListRegistries -> 200 (RPC over D1)
##! GET  /                                                -> 200 HTML (browse)
##! GET  /missing/                                        -> 404 (visibility/miss)
##! ```
##!
##! The browse-HTML assertion is the regression guard for the
##! `std::time::Instant` → `crate::clock::Instant` fix: `Instant::now()` panics on
##! the bare wasm target, which workerd reports as "a hanging Promise was
##! canceled" — a fault invisible to the native tests.
##!
##! ## Why a launcher (not a pure check)
##!
##! `workerd`'s tcmalloc reads `/sys/devices/system/cpu/possible`, which the
##! hermetic Nix build sandbox does not mount, so workerd aborts under
##! `nix-build`. Like the fleet VM tests (which need `/dev/kvm`), this is run
##! **outside** the sandbox: the derivation builds a launcher in-sandbox and the
##! aos test harness / CI `exec`s `$out/bin/aos-registry-worker-e2e` on a real
##! host. The launcher is hermetic in its inputs (every path below is a baked
##! store path); only the *execution* steps outside the sandbox.
{
  mkDerivation,
  aos-registry-worker-dist,
  miniflare,
  nodejs,
  workerd,
  bash,
}: let
  # The miniflare-driven smoke, materialised as a store file so the launcher
  # never embeds it via a fragile nested heredoc.
  e2eScript = builtins.toFile "aos-registry-worker-e2e.mjs" ''
    import { readFileSync } from "node:fs";
    const { Miniflare } = await import(process.env.MF_INDEX);
    const D = process.env.DIST;
    const mf = new Miniflare({
      modules: [
        { type: "ESModule", path: "shim.mjs", contents: readFileSync(D + "/shim.mjs", "utf8") },
        { type: "CompiledWasm", path: "index.wasm", contents: readFileSync(D + "/index.wasm") },
      ],
      compatibilityDate: "2024-09-23",
      compatibilityFlags: ["nodejs_compat"],
      d1Databases: { REGISTRY_DB: "e2e" },
      r2Buckets: ["REGISTRY_BUCKET"],
      kvNamespaces: ["SESSIONS"],
      bindings: {
        HUB_JWT_SECRET: "e2e-jwt-secret",
        HUB_SEAL_KEY: "0000000000000000000000000000000000000000000000000000000000000000",
        HUB_EXTERNAL_URL: "http://localhost",
      },
    });
    let ok = true;
    async function expect(label, path, opts, pred) {
      const r = await mf.dispatchFetch("http://localhost" + path, opts);
      const body = await r.text();
      const good = pred(r.status, body);
      console.log((good ? "ok   " : "FAIL ") + label + " -> " + r.status);
      if (!good) { ok = false; console.error("  body: " + body.slice(0, 160)); }
    }
    try {
      await expect("GET /_init", "/_init", {}, (s, b) => s === 200 && b.includes("schema applied"));
      await expect("POST RPC ListRegistries", "/aos.registry.v1.RegistryService/ListRegistries",
        { method: "POST", body: "{}" }, (s, b) => s === 200 && b.includes("registries"));
      await expect("GET / (browse HTML)", "/", {}, (s, b) => s === 200 && b.includes("<!DOCTYPE html>"));
      await expect("GET /missing/", "/missing/", {}, (s) => s === 404);
    } catch (e) {
      ok = false;
      console.error("E2E threw: " + (e.stack || e.message || e).slice(0, 400));
    }
    await mf.dispose();
    console.log(ok ? "aos-registry-worker e2e: PASS" : "aos-registry-worker e2e: FAIL");
    process.exit(ok ? 0 : 1);
  '';
in
  mkDerivation {
    pname = "aos-registry-worker-e2e";
    version = "0.1.0";

    # The launcher script bakes these store paths and `exec`s them at runtime,
    # so they must survive the scrub phase (which nukes any store ref not
    # reachable from a declared output / runtime / propagated dep).
    runtimeDeps = [aos-registry-worker-dist miniflare nodejs workerd bash];

    # `e2eScript` is a `builtins.toFile` store path (not a derivation), so it
    # isn't in `runtimeDeps`; keep its ref explicitly past the scrub phase.
    nukeRefsKeep = [e2eScript];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-registry-worker-e2e" <<'EOF'
          #!${bash}/bin/bash
          # Run the deployed Worker under miniflare + the from-source workerd and
          # assert the live request surface. Must run OUTSIDE the Nix sandbox:
          # workerd's tcmalloc needs /sys/devices/system/cpu, unavailable there.
          set -euo pipefail
          work="$(mktemp -d)"
          trap 'rm -rf "$work"' EXIT
          cp ${aos-registry-worker-dist}/shim.mjs ${aos-registry-worker-dist}/index.wasm "$work/"
          cp ${e2eScript} "$work/e2e.mjs"
          cd "$work"
          export MINIFLARE_WORKERD_PATH="${workerd}/bin/workerd"
          export MF_INDEX="file://${miniflare}/lib/node_modules/miniflare/dist/src/index.js"
          export DIST="$work"
          exec ${nodejs}/bin/node e2e.mjs
          EOF
          chmod +x "$out/bin/aos-registry-worker-e2e"
        '';
      }
    ];

    meta = {
      description = "Launcher: run the deployed aos-registry-worker wasm under workerd + miniflare and assert the live surface";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
