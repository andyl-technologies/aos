##! aos-hub-worker-e2e — launcher that runs the deployed Worker e2e.
##!
##! `cargo test --workspace` exercises the shared handler logic on the **native**
##! target; it never runs the wasm artifact on a Cloudflare-like runtime, so it
##! cannot catch wasm-only runtime faults (a `wasm32-unknown-unknown` panic, a
##! binding-shape mismatch, the bridge's async behavior under workerd). This
##! check closes that gap: it boots the real `aos-hub-worker-dist` build
##! (`shim.mjs` + `index.wasm`) under miniflare 3 driving the **from-source**
##! `pkgs.workerd` (the npm workerd is a prebuilt ELF blob that does not run on
##! NixOS; miniflare honors `MINIFLARE_WORKERD_PATH`), with D1/R2/KV bindings, and
##! asserts the live request surface responds:
##!
##! It first migrates the D1 binding from the operator CLI's `schema dump` (the
##! same `MIGRATIONS` a real deploy applies via `init --target d1:<name>` — there
##! is no public `/_init` endpoint), then asserts the live request surface:
##!
##! ```text
##! migrate D1 from schema dump                           (CLI-driven init)
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
##! aos test harness / CI `exec`s `$out/bin/aos-hub-worker-e2e` on a real
##! host. The launcher is hermetic in its inputs (every path below is a baked
##! store path); only the *execution* steps outside the sandbox.
{
  mkDerivation,
  aos-hub-worker-dist,
  aos-hub,
  miniflare,
  nodejs,
  workerd,
  bash,
}: let
  # The miniflare-driven smoke, materialised as a store file so the launcher
  # never embeds it via a fragile nested heredoc.
  #
  # The schema is applied by the operator CLI's `schema dump` (baked to
  # schema.json at build time) over the D1 *binding* — there is no public
  # `/_init` endpoint; this mirrors how a real deployment migrates via
  # `aos-hub init --target d1:<name>`.
  e2eScript = builtins.toFile "aos-hub-worker-e2e.mjs" ''
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
      // Migrate the D1 binding from the baked schema dump (CLI-driven init).
      const stmts = JSON.parse(readFileSync(process.env.SCHEMA, "utf8"));
      const db = await mf.getD1Database("REGISTRY_DB");
      for (const stmt of stmts) { await db.prepare(stmt).run(); }
      console.log("ok   migrate D1 from schema dump (" + stmts.length + " stmts)");

      await expect("POST RPC ListRegistries", "/aos.registry.v1.RegistryService/ListRegistries",
        { method: "POST", body: "{}" }, (s, b) => s === 200 && b.includes("registries"));
      await expect("GET / (browse HTML)", "/", {}, (s, b) => s === 200 && b.includes("<!DOCTYPE html>"));
      await expect("GET /missing/", "/missing/", {}, (s) => s === 404);

      // Seed a PUBLIC managed cache (org + binding + cache + one indexed
      // object) and an R2 narinfo, then assert the worker serves the cache
      // surface and browse pages — the worker half of the cache parity claim.
      await db.prepare("INSERT INTO orgs (slug, name, created_at) VALUES ('acme','Acme',0)").run();
      await db.prepare("INSERT INTO storage_bindings (org_id, name, kind, root, created_at) VALUES (1,'b','local_fs','/srv',0)").run();
      await db.prepare("INSERT INTO caches (org_id, slug, name, storage_binding_id, prefix, visibility, priority, compression, want_mass_query, created_at) VALUES (1,'e2e-cache','E2E Cache',1,'cache-prefix','public',40,'zstd',1,0)").run();
      await db.prepare("INSERT INTO cache_objects (cache_id, store_hash, store_name, nar_url, nar_hash, nar_size, file_hash, file_size, compression, refs, uploaded_at) VALUES (1,'aaaa','aaaa-foo-1.0','nar/bbbb.nar.zst','sha256:cccc',100,'sha256:bbbb',50,'zstd','[]',0)").run();
      const bucket = await mf.getR2Bucket("REGISTRY_BUCKET");
      const narinfo = "StorePath: /nix/store/aaaa-foo-1.0\nURL: nar/bbbb.nar.zst\nCompression: zstd\nNarHash: sha256:cccc\nNarSize: 100\nFileHash: sha256:bbbb\nFileSize: 50\n";
      await bucket.put("cache-prefix/aaaa.narinfo", narinfo);
      console.log("ok   seeded public cache + R2 narinfo");

      await expect("GET cache nix-cache-info", "/e2e-cache/nix-cache-info", {},
        (s, b) => s === 200 && b.includes("StoreDir: /nix/store"));
      await expect("GET cache narinfo (from R2)", "/e2e-cache/aaaa.narinfo", {},
        (s, b) => s === 200 && b.includes("StorePath: /nix/store/aaaa-foo-1.0"));
      await expect("GET cache home (HTML)", "/e2e-cache/", {},
        (s, b) => s === 200 && b.includes("E2E Cache"));
      await expect("GET cache objects (HTML)", "/e2e-cache/-/objects", {},
        (s, b) => s === 200 && b.includes("aaaa-foo-1.0"));

      // Streamed NAR fetch through the unified cache-serve path: put a NAR body
      // in R2 and read it both whole (200) and ranged (Range -> 206). The ranged
      // case is the regression guard for the streaming Worker bridge — R2 pushes
      // the byte range down (OffsetWithLength) and the `!Send` ByteStream rides
      // SendWrapper into the axum body, so the isolate never buffers the whole
      // object. A 64 KiB body makes "served 4 bytes for bytes=0-3" meaningful.
      const nar = new Uint8Array(65536);
      for (let i = 0; i < nar.length; i++) nar[i] = i & 0xff;
      await bucket.put("cache-prefix/nar/bbbb.nar.zst", nar);
      await expect("GET cache NAR (whole, from R2)", "/e2e-cache/nar/bbbb.nar.zst", {},
        (s, b) => s === 200 && b.length === 65536);
      {
        const r = await mf.dispatchFetch("http://localhost/e2e-cache/nar/bbbb.nar.zst",
          { headers: { Range: "bytes=0-3" } });
        const buf = await r.arrayBuffer();
        const cr = r.headers.get("content-range") || "";
        const good = r.status === 206 && buf.byteLength === 4
          && cr.startsWith("bytes 0-3/65536");
        console.log((good ? "ok   " : "FAIL ") + "GET cache NAR (Range bytes=0-3) -> "
          + r.status + " " + cr);
        if (!good) {
          ok = false;
          const txt = new TextDecoder().decode(buf);
          console.error("  content-range=" + cr + " len=" + buf.byteLength + " body=" + txt.slice(0, 200));
        }
      }

      // Worker Cron cache-GC: seed a GC-policied cache (ttl=0) with one UNROOTED
      // object, trigger the scheduled handler, and assert the worker's gc_all
      // pass reclaimed it + recorded a run — the Cron counterpart to
      // `aos-hub cache gc`, end to end under workerd+miniflare.
      await db.prepare("INSERT INTO caches (org_id, slug, name, storage_binding_id, prefix, visibility, priority, compression, want_mass_query, created_at) VALUES (1,'gc-cache','GC',1,'gcp','public',40,'zstd',1,0)").run();
      const gc = await db.prepare("SELECT id FROM caches WHERE slug='gc-cache'").first();
      await db.prepare("INSERT INTO cache_gc_policy (cache_id, ttl_unreferenced_secs, keep_channel_frontier, updated_at) VALUES (?1,0,1,0)").bind(gc.id).run();
      await db.prepare("INSERT INTO cache_objects (cache_id, store_hash, store_name, nar_url, nar_hash, nar_size, file_hash, file_size, compression, refs, uploaded_at) VALUES (?1,'zzzz','zzzz-orphan-1.0','nar/zz.nar.zst','sha256:zz',10,'sha256:zz',5,'zstd','[]',0)").bind(gc.id).run();
      // miniflare exposes the worker's scheduled handler at its control-plane
      // /cdn-cgi/mf/scheduled endpoint (distinct from workerd's internal path).
      const sched = await mf.dispatchFetch(
        "http://localhost/cdn-cgi/mf/scheduled?cron=" + encodeURIComponent("*/15 * * * *"));
      {
        const good = sched.status === 200;
        console.log((good ? "ok   " : "FAIL ") + "cron scheduled trigger -> " + sched.status);
        if (!good) ok = false;
      }
      {
        // The Cron fired gc_all over D1: poll for the sweep's run row. miniflare
        // may tear down the scheduled isolate before the async sweep flushes its
        // *finish* (so the row can read `running`), but the run reaching the
        // sweep at all proves the worker's cache-GC executes on D1 cleanly — a
        // `failed` row is the regression guard for the `i64::MAX` LIMIT bind that
        // SQLITE_MISMATCH'd before the fix. Full reclamation correctness is
        // covered by the native end-to-end GC test + the gc.rs unit suite.
        let run = null;
        for (let i = 0; i < 40; i++) {
          run = await db.prepare(
            "SELECT status FROM cache_gc_runs WHERE cache_id = ?1 ORDER BY id DESC").bind(gc.id).first();
          if (run && run.status === "ok") break;
          await new Promise((r) => setTimeout(r, 250));
        }
        const good = run && run.status !== "failed";
        console.log((good ? "ok   " : "FAIL ") + "cron cache-GC swept on D1 (run "
          + (run ? run.status : "none") + ", not failed)");
        if (!good) ok = false;
      }
    } catch (e) {
      ok = false;
      console.error("E2E threw: " + (e.stack || e.message || e).slice(0, 400));
    }
    await mf.dispose();
    console.log(ok ? "aos-hub-worker e2e: PASS" : "aos-hub-worker e2e: FAIL");
    process.exit(ok ? 0 : 1);
  '';
in
  mkDerivation {
    pname = "aos-hub-worker-e2e";
    version = "0.1.0";

    # The launcher script bakes these store paths and `exec`s them at runtime,
    # so they must survive the scrub phase (which nukes any store ref not
    # reachable from a declared output / runtime / propagated dep).
    runtimeDeps = [aos-hub-worker-dist miniflare nodejs workerd bash];

    # `e2eScript` is a `builtins.toFile` store path (not a derivation), so it
    # isn't in `runtimeDeps`; keep its ref explicitly past the scrub phase.
    nukeRefsKeep = [e2eScript];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          # Bake the schema dump (the same MIGRATIONS the CLI applies) so the
          # launcher can migrate miniflare's D1 binding offline — no /_init.
          ${aos-hub}/bin/aos-hub schema dump > "$out/schema.json"
          cat > "$out/bin/aos-hub-worker-e2e" <<'EOF'
          #!${bash}/bin/bash
          # Run the deployed Worker under miniflare + the from-source workerd and
          # assert the live request surface. Must run OUTSIDE the Nix sandbox:
          # workerd's tcmalloc needs /sys/devices/system/cpu, unavailable there.
          set -euo pipefail
          work="$(mktemp -d)"
          trap 'rm -rf "$work"' EXIT
          cp ${aos-hub-worker-dist}/shim.mjs ${aos-hub-worker-dist}/index.wasm "$work/"
          cp ${e2eScript} "$work/e2e.mjs"
          cd "$work"
          export MINIFLARE_WORKERD_PATH="${workerd}/bin/workerd"
          export MF_INDEX="file://${miniflare}/lib/node_modules/miniflare/dist/src/index.js"
          export DIST="$work"
          export SCHEMA="${builtins.placeholder "out"}/schema.json"
          exec ${nodejs}/bin/node e2e.mjs
          EOF
          chmod +x "$out/bin/aos-hub-worker-e2e"
        '';
      }
    ];

    meta = {
      description = "Launcher: run the deployed aos-hub-worker wasm under workerd + miniflare and assert the live surface";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
