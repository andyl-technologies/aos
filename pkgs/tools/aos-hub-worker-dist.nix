##! aos-hub-worker-dist — the deployable Cloudflare Worker artifact, built
##! hermetically from source (RFC-0004).
##!
##! Compiles `crates/aos-hub-worker` to `wasm32-unknown-unknown` and emits
##! the `build/worker/` bundle (the `shim.mjs` ES-module entry plus the
##! `index.wasm` binary) that `wrangler deploy` uploads. The sibling
##! `aos-hub-worker-do-e2e` package boots this artifact under workerd with the
##! production `HubDb` Durable Object topology.
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
  aos-hub-console-dist,
  # Extra cargo feature flags for purpose-built test artifacts. Space-separated;
  # empty for the default production build.
  cargoFeatures ? "",
}: let
  version = "0.1.0";
  repoRoot = ../..;
  repoRootString = toString repoRoot;

  # The Cargo workspace plus its generated API-manifest input are the source.
  # `aos-proto-types` validates that manifest in its build script, so the Worker
  # artifact must carry the same RFC subtree as the native Hub package.
  src = builtins.path {
    path = repoRoot;
    name = "aos-hub-worker-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base != "target"
      && base != ".git"
      && (
        pathString == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
      );
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
    # `aos.nix`/`aos-hub.nix` but its own fixed-output derivation.
    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
    };

    phases = [
      {
        name = "unpack";
        script = ''
          # `src` is a filtered repository `builtins.path` (not a tarball), and
          # store paths are read-only. Copy it into a writable
          # working tree so the configure/build phases can create .cargo/, the
          # target/ dir, and the build/ output.
          cp -r "$src" source
          chmod -R u+w source
          cd source/crates
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
          # aos.hub.v1 message structs (the worker depends on it via
          # aos-hub-core), so point prost-build at the hermetic protoc.
          export PROTOC="${protobuf}/bin/protoc"
          export AOS_HUB_CONSOLE_JS="${aos-hub-console-dist}/hub-console.js"
          export AOS_HUB_CONSOLE_WASM="${aos-hub-console-dist}/hub-console_bg.wasm"
          export AOS_HUB_CONSOLE_CSS="${aos-hub-console-dist}/hub-console.css"
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

          ${lib.optionalString (cargoFeatures == "") ''
            # The disk-backed provider and bootstrap endpoint are permitted only
            # in the purpose-built workerd artifact. Fail the production closure
            # if an e2e route string survives feature gating.
            if grep -a -E -q '/_e2e/|aos_e2e_surface_|workerd-e2e' \
              "$out/shim.mjs" "$out/index.wasm"; then
              echo "worker-dist: do-e2e code leaked into the production artifact" >&2
              exit 1
            fi
          ''}

          # Static assets served by Cloudflare's CDN edge (no Worker invocation).
          # Lay them out under `_assets/` so the on-edge path matches the URL the
          # browse pages + stylesheet reference (e.g. /_assets/style.css), and
          # rename the fonts to the lowercase-hyphenated URL names. The `_headers`
          # file gives stable browse assets a bounded lifetime and the generated,
          # content-addressed console bundle an immutable lifetime.
          mkdir -p "$out/assets/_assets"
          cp aos-hub-core/src/web/static_assets/style.css "$out/assets/_assets/style.css"
          cp aos-hub-core/src/web/static_assets/app.js    "$out/assets/_assets/app.js"
          cp aos-hub-core/src/web/static_assets/JetBrainsMono-Regular.woff2 \
            "$out/assets/_assets/jetbrains-mono-regular.woff2"
          cp aos-hub-core/src/web/static_assets/JetBrainsMono-Bold.woff2 \
            "$out/assets/_assets/jetbrains-mono-bold.woff2"
          cp aos-hub-core/src/web/static_assets/OFL.txt   "$out/assets/_assets/OFL.txt"
          cat aos-hub-core/src/web/static_assets/style.css \
            aos-hub-core/src/web/static_assets/app.js \
            ${aos-hub-console-dist}/hub-console.js \
            ${aos-hub-console-dist}/hub-console_bg.wasm \
            ${aos-hub-console-dist}/hub-console.css \
            > "$TMPDIR/hub-console-version-input"
          # The generated bootstrap is immutable under the same content key.
          # Include its API contract revision so template-only changes cannot
          # leave browsers pinned to an older initializer.
          printf 'bootstrap-api=object-v1\n' \
            >> "$TMPDIR/hub-console-version-input"
          sha256sum "$TMPDIR/hub-console-version-input" \
            > "$TMPDIR/hub-console-version-hash"
          cut -c1-8 "$TMPDIR/hub-console-version-hash" \
            > "$TMPDIR/hub-console-version"
          read -r console_version < "$TMPDIR/hub-console-version"
          cp ${aos-hub-console-dist}/hub-console.js \
            "$out/assets/_assets/hub-console-$console_version.js"
          cp ${aos-hub-console-dist}/hub-console_bg.wasm \
            "$out/assets/_assets/hub-console-''${console_version}_bg.wasm"
          cp ${aos-hub-console-dist}/hub-console.css \
            "$out/assets/_assets/hub-console-$console_version.css"
          printf "import init, { mount } from './hub-console-%s.js';\n\nawait init({ module_or_path: new URL('./hub-console-%s_bg.wasm', import.meta.url) });\nmount();\n" \
            "$console_version" "$console_version" \
            > "$out/assets/_assets/hub-console-bootstrap-$console_version.js"
          printf '/_assets/*\n  Cache-Control: public, max-age=86400\n\n/_assets/hub-console*\n  Cache-Control: public, max-age=31536000, immutable\n' \
            > "$out/assets/_headers"
        '';
      }
    ];

    meta = {
      description = "Deployable AOS registry-hub Cloudflare Worker artifact (wasm + ES-module shim), built from source";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
