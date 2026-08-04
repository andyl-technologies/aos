##! aos-hub-worker-dist — the deployable Cloudflare Worker artifact, built
##! hermetically from source (RFC-0004).
##!
##! Compiles `crates/aos-hub-worker` to `wasm32-unknown-unknown` and emits
##! the `build/worker/` bundle (the `shim.mjs` ES-module entry plus the
##! `index.wasm` binary) that `wrangler deploy` uploads and that miniflare loads
##! via `scriptPath`/`modules`. The RFC-0004 integration VM test
##! (`checks.integration.worker-*`, defined below) boots this artifact under
##! miniflare + workerd inside a Firecracker microVM and drives HTTP requests
##! against the running Worker.
##!
##! ## Why this bypasses `worker-build`'s build engine
##!
##! `pkgs.worker-build` is the upstream wrapper, but it embeds `wasm-pack` as a
##! library and `wasm-pack` *downloads* its tools at build time — it fetches a
##! `wasm-bindgen` matching the crate version and (by default) a `binaryen`
##! `wasm-opt` from the network, with no offline mode plumbed through
##! `worker-build`. Both downloads are fatal in the hermetic Nix sandbox (no
##! network). So this package reproduces `worker-build`'s pipeline directly from
##! AOS-built tools — the same three steps, no network:
##!
##! 1. `cargo build -p aos-hub-worker --target wasm32-unknown-unknown
##!    --release` with the workspace deps vendored offline by `fetchCargoDeps`.
##!    The `wasm32` std + `rust-lld` linker ship in `pkgs.rust` already.
##! 2. `wasm-bindgen --target bundler` (`pkgs.wasm-bindgen-cli`, version-locked
##!    to the crate's `wasm-bindgen` 0.2.125) generates `index_bg.js` +
##!    `index_bg.wasm` (and, for `worker` 0.8, a `snippets/` dir holding the
##!    crate's inline-JS panic-recovery state).
##! 3. The exact `worker-build` post-processing: rewrite the bindgen glue to
##!    import the WASM via a `glue.js` instantiation shim, drop in
##!    `worker-build`'s `shim.js` event-handler glue, and bundle the lot into a
##!    single `shim.mjs` ES module with `esbuild` (the native `esbuild` binary
##!    from the vendored `pkgs.miniflare` closure; `index.wasm` is kept external,
##!    so the bundle plus the sibling `index.wasm` are the two deploy modules).
##!
##! ## wasm-opt
##!
##! Skipped entirely. `wasm-opt` (binaryen) is a size/speed *optimizer*; the
##! Worker is correct and runnable without it, and `binaryen` is not packaged
##! for AOS. `worker-build`/`wasm-pack` only run it as optional polish (and only
##! when binaryen is present), so omitting it changes nothing about behavior.
##! Packaging `pkgs.binaryen` from source is the natural follow-on if artifact
##! size ever matters.
##!
##! ## Output layout
##!
##! ```text
##! $out/shim.mjs    the bundled ES-module Worker entry (the wrangler `main`)
##! $out/index.wasm  the wasm-bindgen module the shim imports
##! $out/assets/     first-party static files (CSS/JS/fonts under _assets/)
##!                  served directly by Cloudflare's CDN edge — see below
##! ```
##!
##! ## Static assets bypass the Worker
##!
##! The browse stylesheet, progressive-enhancement JS, and fonts are copied into
##! `$out/assets/_assets/` and declared to `wrangler` via an `[assets]` directory
##! binding. Cloudflare serves any request whose path matches a file there
##! *before* invoking the Worker, so `GET /_assets/*` is answered from the CDN
##! edge with no wasm instantiation — eliminating the per-request Worker spin-up
##! that an embedded-bytes handler would pay. The same bytes are embedded in the
##! native hub via `aos_hub_core::web::assets`, so the files in
##! `crates/aos-hub-core/src/web/static_assets/` are the single source of truth;
##! only the delivery differs (the native hub has no CDN and serves them itself).
{
  lib,
  mkDerivation,
  fetchCargoDeps,
  rust,
  wasm-bindgen-cli,
  miniflare,
  nodejs,
  protobuf,
  stdenv,
  # Extra cargo feature flags for the worker build (e.g. "cutover-admin" for the
  # one-time D1->HubDb data-replay admin path). Space-separated; empty for the
  # default production build. RFC-0004 ch.14 Phase E.
  cargoFeatures ? "",
}: let
  version = "0.1.0";

  # The whole cargo workspace is the source: the worker depends on the
  # in-workspace `aos-registry-surface` crate, and the workspace `Cargo.lock`
  # pins every transitive dependency. Mirrors `pkgs/tools/aos/aos.nix`.
  src = builtins.path {
    path = ../../crates;
    name = "aos-crates-src";
    filter = path: _type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };

  # The native `esbuild` binary inside the vendored miniflare/wrangler closure
  # (the platform package, not the `#!/usr/bin/env node` JS launcher).
  esbuildBin = "${miniflare}/lib/node_modules/@esbuild/linux-x64/bin/esbuild";
in
  mkDerivation {
    pname = "aos-hub-worker-dist";
    inherit version src;

    # The wasm32 toolchain (rustc + cargo + the wasm32 std + rust-lld), the
    # version-locked bindgen CLI, node for the glue-rewrite script, and a host
    # `cc` on PATH for any build-script native compile during the cargo build.
    buildDeps = [rust wasm-bindgen-cli nodejs protobuf stdenv.cc];

    # The workspace's vendored dependency set, fetched offline. Same shape as
    # `aos.nix`/`aos-hub.nix` but its own FOD. Iterate fakeHash → real.
    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
    };

    phases = [
      {
        name = "unpack";
        script = ''
          # `src` is a `builtins.path` of the crates/ workspace directory (not a
          # tarball), and store paths are read-only. Copy it into a writable
          # working tree so the configure/build phases can create .cargo/, the
          # target/ dir, and the build/ output.
          cp -r "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          # fetchCargoDeps layout: a raw vendor directory. Wire it as the
          # crates.io replacement so the offline build resolves every dep.
          printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "%s"\n\n' \
            "$cargoDeps" > .cargo/config.toml
        '';
      }
      {
        name = "build-wasm";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          # aos-proto-types' build script runs protoc to generate the
          # aos.registry.v1 message structs (the worker depends on it via
          # aos-hub-core), so point prost-build at the hermetic protoc.
          export PROTOC="${protobuf}/bin/protoc"
          # Step 1 — compile the worker cdylib to wasm32. rust-lld (shipped in
          # pkgs.rust's rustlib bin) is the wasm linker; no env override needed.
          #
          # Features are passed package-qualified (`aos-hub-worker/<feat>`): a
          # bare `--features <feat>` with `-p` in this virtual workspace is
          # silently dropped (the cfg never activates), so the qualified form is
          # the reliable one.
          cargo build \
            -p aos-hub-worker \
            --target wasm32-unknown-unknown \
            --release \
            --frozen \
            --offline \
            ${lib.optionalString (cargoFeatures != "") "--features ${
            lib.concatMapStringsSep "," (f: "aos-hub-worker/${f}") (lib.splitString " " cargoFeatures)
          }"} \
            -j"$NIX_BUILD_CORES"

          test -f target/wasm32-unknown-unknown/release/aos_hub_worker.wasm
        '';
      }
      {
        name = "bindgen";
        script = ''
          # Step 2 — wasm-bindgen with the bundler target, producing
          # build/index_bg.js + build/index_bg.wasm (the OUT_NAME=index names
          # worker-build's post-processing expects).
          mkdir -p build
          wasm-bindgen \
            --target bundler \
            --no-typescript \
            --out-dir build \
            --out-name index \
            target/wasm32-unknown-unknown/release/aos_hub_worker.wasm
        '';
      }
      {
        name = "bundle";
        script = ''
          # Step 3 — replicate worker-build's worker-dir assembly + esbuild
          # bundle. Lay out build/worker/ exactly as worker-build does: the
          # bindgen wasm is renamed index.wasm; the glue keeps index_bg.js.
          mkdir -p build/worker
          mv build/index_bg.js   build/worker/index_bg.js
          mv build/index_bg.wasm build/worker/index.wasm
          # worker 0.8's glue imports an inline-JS snippet (the panic-recovery
          # `state`) via a relative `./snippets/...` path, so the directory must
          # travel alongside index_bg.js for esbuild to resolve the import.
          if [ -d build/snippets ]; then
            cp -r build/snippets build/worker/snippets
          fi

          # glue.js — instantiates the wasm and re-exports its exports
          # (worker-build src/js/glue.js, verbatim).
          cat > build/worker/glue.js << 'GLUE'
          import wasmModule from './index.wasm';
          import * as imports from './index_bg.js';

          const instance = new WebAssembly.Instance(wasmModule, { "./index_bg.js": imports });
          export default instance.exports;
          GLUE

          # shim.js — worker-build's event-handler entry (src/js/shim.js,
          # verbatim). It wires fetch/queue/scheduled to the wasm exports.
          cat > build/worker/shim.js << 'SHIM'
          import * as imports from "./index_bg.js";
          export * from "./index_bg.js";
          import wasmModule from "./index.wasm";
          import { WorkerEntrypoint } from "cloudflare:workers";

          // Run the worker's initialization function.
          imports.start?.();

          export { wasmModule };

          class Entrypoint extends WorkerEntrypoint {
              async fetch(request) {
                  return await imports.fetch(request, this.env, this.ctx)
              }

              async queue(batch) {
                  return await imports.queue(batch, this.env, this.ctx)
              }

              async scheduled(event) {
                  return await imports.scheduled(event, this.env, this.ctx)
              }
          }

          const EXCLUDE_EXPORT = [
              "IntoUnderlyingByteSource",
              "IntoUnderlyingSink",
              "IntoUnderlyingSource",
              "MinifyConfig",
              "PolishConfig",
              "R2Range",
              "RequestRedirect",
              "fetch",
              "queue",
              "scheduled",
              "getMemory"
          ];

          Object.keys(imports).map(k => {
              if (!(EXCLUDE_EXPORT.includes(k) | k.startsWith("__"))) {
                  Entrypoint.prototype[k] = imports[k];
              }
          })

          export default Entrypoint;
          SHIM

          # Rewrite the bindgen glue's wasm provision so the wasm is supplied by
          # glue.js (worker-build's use_glue_import). Crucially, `wasm` stays a
          # mutable `let` initialized from glue.js — `worker` 0.8's glue also
          # ships a `__wbg_reset_state` panic-recovery path that *reassigns*
          # `wasm` (`wasm = wasmInstance.exports`), so importing it as a `const`
          # binding makes esbuild reject the bundle ("Cannot assign to import").
          # `__wbg_set_wasm` is retained for the same reason.
          REWRITE_JS="$TMPDIR/glue-rewrite.mjs"
          {
          printf '%s\n' "import { readFileSync, writeFileSync } from 'node:fs';"
          printf '%s\n' "const p = process.argv[2];"
          printf '%s\n' "let s = readFileSync(p, 'utf8');"
          # Match the bindgen `let wasm;` + `__wbg_set_wasm` setter regardless of
          # the exact whitespace/blank-line shape the bindgen version emits, and
          # replace it with a glue.js import that keeps `wasm` reassignable.
          printf '%s\n' "const re = /let wasm;\\s*export function __wbg_set_wasm\\(val\\)\\s*\\{\\s*wasm = val;\\s*\\}/;"
          printf '%s\n' "if (!re.test(s)) {"
          printf '%s\n' "  console.error('worker-dist: bindgen glue preamble mismatch; head was:');"
          printf '%s\n' "  console.error(s.slice(0, 400));"
          printf '%s\n' "  process.exit(1);"
          printf '%s\n' "}"
          printf '%s\n' "const B = \"\\nimport __wbg_glue from './glue.js';\\nlet wasm = __wbg_glue;\\nexport function __wbg_set_wasm(val) { wasm = val; }\\n\\nexport function getMemory() {\\n    return wasm.memory;\\n}\\n\";"
          printf '%s\n' "writeFileSync(p, s.replace(re, B));"
          } > "$REWRITE_JS"
          node "$REWRITE_JS" build/worker/index_bg.js

          # Bundle shim.js + its imports into one shim.mjs. index.wasm is kept
          # external so the deploy surface is { shim.mjs, index.wasm }. The
          # cloudflare: builtins are provided by the runtime, never bundled.
          ( cd build/worker
            "${esbuildBin}" \
              --external:./index.wasm \
              --external:cloudflare:sockets \
              --external:cloudflare:workers \
              --format=esm \
              --bundle \
              ./shim.js \
              --outfile=shim.mjs )

          # Install the deploy surface: the bundled shim plus the wasm module.
          mkdir -p "$out"
          cp build/worker/shim.mjs   "$out/shim.mjs"
          cp build/worker/index.wasm "$out/index.wasm"

          # Static assets served by Cloudflare's CDN edge (no Worker invocation).
          # Lay them out under `_assets/` so the on-edge path matches the URL the
          # browse pages + stylesheet reference (e.g. /_assets/style.css), and
          # rename the fonts to the lowercase-hyphenated URL names. The `_headers`
          # file sets a browser cache lifetime; Cloudflare edge-caches them
          # regardless. (Names are stable, not content-hashed, so the lifetime is
          # bounded rather than `immutable` — hashing is the follow-on if needed.)
          mkdir -p "$out/assets/_assets"
          cp aos-hub-core/src/web/static_assets/style.css "$out/assets/_assets/style.css"
          cp aos-hub-core/src/web/static_assets/app.js    "$out/assets/_assets/app.js"
          cp aos-hub-core/src/web/static_assets/JetBrainsMono-Regular.woff2 \
            "$out/assets/_assets/jetbrains-mono-regular.woff2"
          cp aos-hub-core/src/web/static_assets/JetBrainsMono-Bold.woff2 \
            "$out/assets/_assets/jetbrains-mono-bold.woff2"
          cp aos-hub-core/src/web/static_assets/OFL.txt   "$out/assets/_assets/OFL.txt"
          printf '/_assets/*\n  Cache-Control: public, max-age=86400\n' \
            > "$out/assets/_headers"
        '';
      }
    ];

    # The RFC-0004 worker integration test. Exposed as a package `checks` attr
    # (→ `checks.integration.aos-hub-worker-dist-read-path`) rather than
    # `checks.vm.*`, because `checks.vm.*` is currently un-evaluable on this
    # branch (a pre-existing `mkOption defaultText` bug in lib/modules.nix breaks
    # the systems-module eval that `checks.vm` forces). `checks.integration.*`
    # evals cleanly. The test boots node + miniflare + workerd in a headless
    # Firecracker microVM, loads this artifact, seeds D1 + R2 with a signed
    # public registry surface (pkgs.aos-hub-worker-fixture), and drives HTTP
    # requests against the running Worker.
    checks = {
      testing,
      self,
      pkgs,
    }: let
      fixture = pkgs.aos-hub-worker-fixture;
      miniflareJs = "${pkgs.miniflare}/lib/node_modules/miniflare/dist/src/index.js";

      # The Node ESM driver: construct Miniflare around the built Worker, seed
      # D1 + R2, dispatch requests, assert the read-path behavior (facade
      # fidelity, 404, browse render, visibility gating, Cron indexer), and print
      # PASS/FAIL lines. Written to /tmp in the guest and run with AOS node 22
      # (global `fetch`/`Response` available; the driver uses dispatchFetch).
      driver = ''
        import { Miniflare } from "${miniflareJs}";
        import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
        import { join, relative } from "node:path";

        const DIST = "${self}";
        const SURFACE = "${fixture}/surface";
        const TRUST_KEY = readFileSync("${fixture}/trust_key", "utf8").trim();

        let failures = 0;
        // Hard assertion: a failure fails the whole test. The entire read +
        // indexer surface now runs on core::Database over the D1Backend (f64
        // integer binds, NULL-tolerant reads), so every check is hard — there
        // are no longer any pinned-workerd D1 quirks to soft-defer.
        function check(name, cond, detail) {
          if (cond) console.log("PASS: " + name);
          else { failures++; console.log("FAIL: " + name + (detail ? " — " + detail : "")); }
        }

        // Recursively list every file under a directory as POSIX-relative paths.
        function walk(dir, base) {
          const out = [];
          for (const ent of readdirSync(dir)) {
            const p = join(dir, ent);
            if (statSync(p).isDirectory()) out.push(...walk(p, base));
            else out.push(relative(base, p));
          }
          return out;
        }

        const mf = new Miniflare({
          // The Worker is an ES module with a sibling wasm import; provide both
          // as explicit modules. modulesRoot lets the shim's `./index.wasm`
          // import resolve to the CompiledWasm module.
          modules: [
            { type: "ESModule", path: join(DIST, "shim.mjs") },
            { type: "CompiledWasm", path: join(DIST, "index.wasm") },
          ],
          modulesRoot: DIST,
          compatibilityDate: "2024-09-23",
          d1Databases: { REGISTRY_DB: "registry-db" },
          r2Buckets: { REGISTRY_BUCKET: "registry-bucket" },
          kvNamespaces: { SESSIONS: "sessions" },
        });
        await mf.ready;

        // ── Seed D1: schema, a PUBLIC `demo` registry (R2 prefix `demo`) with
        // the fixture's pinned trust key + signatures required, a PRIVATE
        // `secret` registry, and one package row so the browse UI renders. ──
        const db = await mf.getD1Database("REGISTRY_DB");
        // Create the schema the *shared* way: dispatch the Worker's /_init, which
        // constructs core::Database over the D1Backend and applies the exact core
        // MIGRATIONS the native hub uses — not a Worker-local schema subset. The
        // D1Backend binds integers as JS numbers (f64), so the migration's
        // schema-version write runs cleanly even under the pinned 2024-09-09
        // workerd seed (whose D1 rejects BigInt binds).
        const initRes = await mf.dispatchFetch("http://localhost/_init");
        check("schema /_init applied", initRes.status === 200, "got " + initRes.status);
        await db.prepare(
          "INSERT INTO registries (id, slug, source_url, trust_keys, require_signatures, created_at, visibility, prefix) " +
          "VALUES (1, 'demo', 'file:///demo', ?1, 1, 100, 'public', 'demo')"
        ).bind(JSON.stringify([TRUST_KEY])).run();
        await db.prepare(
          "INSERT INTO registries (id, slug, source_url, trust_keys, require_signatures, created_at, visibility, prefix) " +
          "VALUES (2, 'secret', 'file:///secret', '[]', 1, 100, 'private', 'secret')"
        ).run();
        await db.prepare(
          "INSERT INTO packages (id, registry_id, name, description, license, maintainer, sysroot) " +
          "VALUES (1, 1, 'curl', 'Command-line URL transfers', 'MIT', 'aos', 0)"
        ).run();
        await db.prepare(
          "INSERT INTO package_versions (id, package_id, version, previous) VALUES (1, 1, '8.5.0', NULL)"
        ).run();

        // ── Seed R2: every fixture surface file under the `demo/` prefix (the
        // registry's R2 key prefix). Mirrors `apr origin upload`'s layout. ──
        const bucket = await mf.getR2Bucket("REGISTRY_BUCKET");
        // Put bodies as ArrayBuffer (a freshly sliced copy, not a Buffer view
        // over a pooled allocation): miniflare's API proxy serializes
        // ArrayBuffer cleanly, whereas a Node Buffer trips its devalue
        // ArrayBufferView assertion.
        const toArrayBuffer = (buf) =>
          buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
        const putR2 = (key, buf) => bucket.put(key, toArrayBuffer(buf));
        for (const rel of walk(SURFACE, SURFACE)) {
          const body = readFileSync(join(SURFACE, rel));
          await putR2("demo/" + rel.split("\\").join("/"), body);
        }

        const ORIGIN = "http://localhost";
        const get = (p) => mf.dispatchFetch(ORIGIN + p);

        // ── (a) Facade fidelity: nix-cache-info, a narinfo, and a NAR return
        // the exact R2 bytes with the right content-type/cache-control. ──
        {
          const r = await get("/demo/nix-cache-info");
          const body = await r.text();
          const expected = readFileSync(join(SURFACE, "nix-cache-info"), "utf8");
          check("facade nix-cache-info status 200", r.status === 200, "got " + r.status);
          check("facade nix-cache-info bytes", body === expected);
          check("facade nix-cache-info content-type",
            r.headers.get("content-type") === "text/plain; charset=utf-8",
            r.headers.get("content-type"));
          check("facade nix-cache-info cache-control",
            r.headers.get("cache-control") === "public, max-age=60, must-revalidate",
            r.headers.get("cache-control"));
        }
        {
          const r = await get("/demo/h7j3k8l2m9n4.narinfo");
          const body = await r.text();
          const expected = readFileSync(join(SURFACE, "h7j3k8l2m9n4.narinfo"), "utf8");
          check("facade narinfo status 200", r.status === 200, "got " + r.status);
          check("facade narinfo bytes", body === expected);
          check("facade narinfo content-type",
            r.headers.get("content-type") === "text/x-nix-narinfo",
            r.headers.get("content-type"));
        }
        {
          const r = await get("/demo/nar/h7j3k8l2m9n4.nar.zst");
          const buf = Buffer.from(await r.arrayBuffer());
          const expected = readFileSync(join(SURFACE, "nar/h7j3k8l2m9n4.nar.zst"));
          check("facade nar status 200", r.status === 200, "got " + r.status);
          check("facade nar bytes", buf.equals(expected));
          check("facade nar content-type",
            r.headers.get("content-type") === "application/zstd",
            r.headers.get("content-type"));
          check("facade nar cache-control immutable",
            r.headers.get("cache-control") === "public, max-age=31536000, immutable",
            r.headers.get("cache-control"));
        }

        // ── (b) 404: a missing object and an unknown registry both 404. ──
        {
          const r1 = await get("/demo/nar/does-not-exist.nar.zst");
          check("missing object is 404", r1.status === 404, "got " + r1.status);
          // Unknown-registry → `registry_by_slug` finds no row → core's
          // `query_opt` yields a clean `None` (no row), so the worker 404s. This
          // resolves cleanly under the pinned workerd now that the read path
          // runs core::Database over the D1Backend (the old worker-crate
          // `.first(None)` null path 500'd on serde-wasm-bindgen). Hard.
          const r2 = await get("/nope/nix-cache-info");
          check("unknown registry is 404", r2.status === 404, "got " + r2.status);
        }

        // ── (c) Browse render: the registry home + package table render the
        // seeded registry/package as no-JS HTML. ──
        {
          // The hub home (`list_public_registries` → D1 `.all()`) is fully
          // green under the seed; assert it hard.
          const home = await get("/");
          const homeBody = await home.text();
          check("hub home status 200", home.status === 200, "got " + home.status);
          check("hub home lists 'demo'", homeBody.includes("demo"));

          // The per-registry package table binds `registry_id` (an i64). The
          // read path now runs core::Database over the D1Backend, which binds
          // integers as JS numbers (f64), not the `worker` crate's BigInt that
          // the pinned 2024-09-09 workerd D1 rejected (D1_TYPE_ERROR). So
          // browse-by-registry resolves cleanly now. Hard. (The Cron indexer
          // WRITE path also runs over the D1Backend now — see below.)
          const r = await get("/demo/-/packages");
          const body = await r.text();
          check("browse packages status 200", r.status === 200, "got " + r.status);
          check("browse packages contains 'curl'", body.includes("curl"));
        }

        // ── (d) Visibility gating: the PRIVATE registry is not served on the
        // anonymous read path (404 for both facade and browse). ──
        {
          // Private gating: `Reads::registry_by_slug` applies the
          // `visibility == "public"` filter, so a private registry yields a
          // clean `None` → 404. Now that the read path runs core::Database (the
          // old worker-crate null path 500'd under the pinned workerd), this
          // resolves to a real 404. Hard. (The private surface is never served:
          // both the 404 and the not-200 invariant hold.)
          const r1 = await get("/secret/nix-cache-info");
          check("private registry facade not served (404 expected)", r1.status === 404, "got " + r1.status);
          check("private registry facade does NOT leak bytes (not 200)", r1.status !== 200, "got " + r1.status);
          const r2 = await get("/secret/-/packages");
          check("private registry browse not served (404 expected)", r2.status === 404, "got " + r2.status);
          check("private registry browse does NOT leak (not 200)", r2.status !== 200, "got " + r2.status);
        }

        // ── (e) Cron indexer: dispatch the scheduled event; it walks the R2
        // surface into D1 with full Ed25519 verification + anti-rollback floor.
        // After a clean run the registry indexes `fresh`, the release + channel
        // are recorded, and the channel floor is raised to the frontier. ──
        // miniflare exposes a worker's scheduled handler at its control-plane
        // `/cdn-cgi/mf/scheduled` endpoint (query params `cron`/`time`); this is
        // miniflare's own hook, distinct from workerd's internal
        // `/cdn-cgi/handler/scheduled`. Dispatch it to drive the Cron indexer.
        const triggerScheduled = () =>
          mf.dispatchFetch(ORIGIN + "/cdn-cgi/mf/scheduled?cron=" + encodeURIComponent("*/15 * * * *"));

        // The Cron indexer reads the R2 surface (verifying every signature via
        // the shared `aos-registry-surface` reader) and writes the D1 index over
        // the D1Backend — same engine as the read path, so its `i64` id binds
        // cross as JS numbers and succeed under the pinned workerd. After a clean
        // run the registry indexes `fresh`, the release + channel are recorded,
        // and the anti-rollback floor is raised to the frontier. All hard.
        {
          const sr = await triggerScheduled();
          check("scheduled trigger accepted", sr.status === 200, "got " + sr.status);

          const idx = await db.prepare(
            "SELECT state FROM registry_index WHERE registry_id = 1"
          ).first();
          check("indexer set registry fresh", idx && idx.state === "fresh",
            idx ? idx.state : "no row");

          const rel = await db.prepare(
            "SELECT semver FROM releases WHERE registry_id = 1"
          ).first();
          check("indexer recorded release 1.0.0", rel && rel.semver === "1.0.0",
            rel ? rel.semver : "no row");

          const ch = await db.prepare(
            "SELECT name, frontier FROM channels WHERE registry_id = 1"
          ).first();
          check("indexer recorded channel stable @ 1.0.0",
            ch && ch.name === "stable" && ch.frontier === "1.0.0",
            ch ? (ch.name + "@" + ch.frontier) : "no row");

          const floor = await db.prepare(
            "SELECT floor FROM channel_floors WHERE registry_id = 1 AND channel = 'stable'"
          ).first();
          check("indexer raised anti-rollback floor to 1.0.0",
            floor && floor.floor === "1.0.0", floor ? floor.floor : "no row");
        }

        // ── (e′) Fail-closed: corrupt the HEAD commit's signature in R2 and
        // re-index a SECOND registry pointing at the tampered prefix. Nothing
        // must be recorded (the index fails closed) and the prior good index of
        // `demo` must be untouched. ──
        {
          // Tamper: overwrite the demo HEAD commit object with garbage under a
          // fresh prefix `bad/`, copying the rest of the surface verbatim.
          for (const rel of walk(SURFACE, SURFACE)) {
            const body = readFileSync(join(SURFACE, rel));
            await putR2("bad/" + rel.split("\\").join("/"), body);
          }
          // Flip the HEAD commit loose object to break its signature.
          await bucket.put("bad/HEAD", "ref: refs/heads/stable\n");
          // Corrupt the commit object: replace it with an unrelated valid-zlib
          // blob is complex; instead corrupt info/refs so the advertised HEAD
          // commit is absent — the indexer fails closed (missing object).
          await bucket.put("bad/objects/00/00", "garbage");

          await db.prepare(
            "INSERT INTO registries (id, slug, source_url, trust_keys, require_signatures, created_at, visibility, prefix) " +
            "VALUES (3, 'bad', 'file:///bad', ?1, 1, 100, 'public', 'bad')"
          ).bind(JSON.stringify([TRUST_KEY])).run();
          // Point bad's HEAD commit at a non-existent oid via a tampered refs.
          await bucket.put("bad/info/refs",
            "0000000000000000000000000000000000000000000000000000000000000000\trefs/heads/stable\n");

          await triggerScheduled();

          const badIdx = await db.prepare(
            "SELECT state FROM registry_index WHERE registry_id = 3"
          ).first();
          check("fail-closed: bad registry not fresh",
            !badIdx || badIdx.state !== "fresh", badIdx ? badIdx.state : "no row");
          const badRel = await db.prepare(
            "SELECT COUNT(*) AS n FROM releases WHERE registry_id = 3"
          ).first();
          // n comes back from D1 as a number; never any release rows for `bad`.
          check("fail-closed: bad registry recorded no releases",
            badRel && Number(badRel.n) === 0, badRel ? String(badRel.n) : "no row");
        }

        await mf.dispose();

        console.log("SUMMARY: hard-failures=" + failures);

        if (failures === 0) {
          // Write a sentinel the shell can test with coreutils alone (the VM
          // guest has no grep). The marker line is also printed for the log.
          writeFileSync("/tmp/worker-ok", "ok\n");
          console.log("WORKER_READPATH:OK");
        } else {
          console.log("WORKER_READPATH:FAIL (" + failures + " hard failures)");
          process.exit(1);
        }
      '';
    in {
      read-path = testing.mkVMTest {
        name = "aos-hub-worker-read-path";
        # node + miniflare + workerd + the wasm worker is memory-hungry; give
        # the microVM generous headroom.
        memory = 2048;
        rootfsDeps = [
          pkgs.nodejs
          pkgs.miniflare
          pkgs.workerd-source
          self
          fixture
          pkgs.coreutils
          # miniflare's dispatchFetch connects to workerd over 127.0.0.1, so the
          # loopback interface must be up — bring it up with iproute2's `ip`.
          pkgs.iproute2
        ];
        testScript = ''
          echo "==> bringing up loopback (miniflare ↔ workerd talk over 127.0.0.1)"
          ${pkgs.iproute2}/sbin/ip link set lo up

          echo "==> writing worker integration driver"
          cat > /tmp/driver.mjs << 'DRIVER_EOF'
          ${driver}
          DRIVER_EOF

          echo "==> running miniflare + workerd against the built worker"
          # miniflare honors MINIFLARE_WORKERD_PATH to use the from-source AOS
          # workerd (built via AOS Bazel) instead of the npm blob in its closure.
          export MINIFLARE_WORKERD_PATH="${pkgs.workerd-source}/bin/workerd"
          export HOME=/tmp

          # A top-level throw in the ESM driver must fail the test. Run node
          # directly (no pipe, so its exit status propagates), then require the
          # success sentinel the driver writes — so a silent partial run cannot
          # masquerade as a pass. The VM guest has no grep, hence the file
          # sentinel checked with coreutils `test`.
          rm -f /tmp/worker-ok
          rc=0
          ${pkgs.nodejs}/bin/node /tmp/driver.mjs || rc=$?
          echo "==> driver exit code: $rc"
          if [ "$rc" -ne 0 ]; then
            echo "==> driver failed (exit $rc)"
            exit 1
          fi
          if [ ! -f /tmp/worker-ok ]; then
            echo "==> driver did not write the success sentinel"
            exit 1
          fi
          echo "==> worker read-path assertions all passed"
        '';
      };
    };

    meta = {
      description = "Deployable AOS registry-hub Cloudflare Worker artifact (wasm + ES-module shim), built from source";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
