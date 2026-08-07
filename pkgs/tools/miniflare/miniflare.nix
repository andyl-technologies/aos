##! miniflare + wrangler — Cloudflare's local Workers test tooling, vendored
##! hermetically for the RFC-0004 registry-worker tests.
##!
##! This package vendors the full npm dependency closure of `wrangler` (4.x) and
##! `miniflare` (3.x) — including the native `better-sqlite3` addon that miniflare
##! uses for local D1/KV storage — and exposes the `wrangler`/`miniflare` CLIs
##! runnable under AOS node. No host node, no host npm, no nixpkgs.
##!
##! ## Two-stage build (the npm analogue of cargo vendoring)
##!
##! 1. `fetchNpmDeps` (a fixed-output derivation) runs `npm ci --ignore-scripts`
##!    against the committed `package.json` + `package-lock.json` next to this
##!    file. `npm ci` installs the lockfile *exactly* (no resolution), so the
##!    output is deterministic. Scripts are skipped so the FOD output is a pure
##!    JS tree with no store-path references (a FOD must not reference the store).
##! 2. This `mkDerivation` (a normal, store-referencing build) copies the vendored
##!    tree, compiles `better-sqlite3` from source with node-gyp against AOS node
##!    headers + the ccWrapper gcc, and emits the two CLI wrappers.
##!
##! ## better-sqlite3 (native addon)
##!
##! `better-sqlite3` ships C++ compiled by node-gyp. Its npm install script
##! (`prebuild-install || node-gyp rebuild`) would otherwise download a
##! host-prebuilt `.node` blob — non-hermetic — so we skip it in the FOD and
##! drive node-gyp directly here. `--nodedir=${nodejs}` makes node-gyp use AOS
##! node headers offline; `python3` + the ccWrapper gcc/`gnumake` satisfy the
##! toolchain; the result lands at `build/Release/better_sqlite3.node`.
##!
##! ## workerd (DEFERRED — host-binary blob)
##!
##! miniflare spawns Cloudflare's `workerd` runtime to actually execute Workers.
##! The npm `workerd` package resolves its binary from a platform package
##! (`@cloudflare/workerd-linux-64/bin/workerd`), a prebuilt ELF blob. That
##! violates the hermetic-from-source rule, so we DO NOT rely on it executing.
##! On linux-x64 the optional platform package is still pulled into the vendored
##! tree (it matches the os/cpu), but a from-source workerd (built via AOS Bazel
##! in a follow-on task) is the real target. To swap it in, either point miniflare
##! at the from-source binary via the `MINIFLARE_WORKERD_PATH` environment
##! variable (miniflare honors it) or replace the ELF at
##! `node_modules/@cloudflare/workerd-linux-64/bin/workerd` in the closure.
##!
##! The "done" bar for this package is that the npm tree vendors deterministically
##! and the `wrangler`/`miniflare` JS CLIs load and print version/help under AOS
##! node — not that workerd can spawn yet.
{
  mkDerivation,
  fetchNpmDeps,
  nodejs,
  python3,
  gnumake,
  bash,
}: let
  # Wrangler 4.36.0 introduced Worker Rate Limiting binding uploads. Older
  # releases accept `[[ratelimits]]` but omit those bindings at deploy time,
  # leaving the Hub runtime unable to serve application requests.
  version = "wrangler-4.119.0+miniflare-3.20240909.0";

  # The committed manifest + lockfile live next to this file. Filter the source
  # to just those two inputs so unrelated edits (e.g. to this .nix) don't churn
  # the vendoring derivation's inputs.
  npmSrc = builtins.path {
    name = "miniflare-npm-manifest";
    path = ./.;
    filter = path: _type: let
      base = baseNameOf path;
    in
      base == "package.json" || base == "package-lock.json";
  };

  nodeModules = fetchNpmDeps {
    name = "miniflare-tooling-node-modules";
    src = npmSrc;
    # Iterate: fakeHash → real hash from the mismatch error.
    hash = "sha256-RXKP78tXoES9TA9m7Y7lGic+BgicQW1mXzXck7vXy2k=";
  };
in
  mkDerivation {
    pname = "miniflare";
    inherit version;

    # No upstream source archive: the package content is the vendored
    # node_modules plus generated wrapper scripts.
    src = null;

    buildDeps = [nodejs python3 gnumake];
    runtimeDeps = [nodejs];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/lib $out/bin

          # Place the vendored dependency tree under $out/lib/node_modules so
          # node's module resolution finds it relative to the wrapped entry JS.
          cp -a ${nodeModules} $out/lib/node_modules
          chmod -R u+w $out/lib/node_modules
          NM=$out/lib/node_modules

          # Compile better-sqlite3's native addon from source. node-gyp ships
          # inside npm; invoke its JS entry through node directly to avoid the
          # `#!/usr/bin/env node` shebang (no /usr/bin/env in the sandbox).
          nodeGyp=${nodejs}/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js
          ( cd $NM/better-sqlite3
            ${nodejs}/bin/node "$nodeGyp" rebuild \
              --release \
              --nodedir=${nodejs} \
              --python=${python3}/bin/python3 )

          # Sanity-check the compiled addon is present.
          test -f $NM/better-sqlite3/build/Release/better_sqlite3.node

          # CLI wrappers: AOS bash execs AOS node on the vendored JS entrypoint.
          # The npm-generated .bin shims carry host-style `/usr/bin/env` shebangs,
          # so we bypass them. The wrapper must run node with the entry as the
          # *main module* (e.g. wrangler.js gates its launch on
          # `module === require.main`), so a bash `exec node <entry> "$@"` wrapper
          # is used rather than a `require()` shim. The bash shebang points at AOS
          # bash, satisfying the no-/usr/bin/env, no-/bin/sh rule.

          # wrangler: bin/wrangler.js (CommonJS; spawns wrangler-dist/cli.js)
          printf '#!%s\nexec %s "%s/wrangler/bin/wrangler.js" "$@"\n' \
            "${bash}/bin/bash" "${nodejs}/bin/node" "$NM" \
            > $out/bin/wrangler
          chmod +x $out/bin/wrangler

          # miniflare: bootstrap.js (CommonJS)
          printf '#!%s\nexec %s "%s/miniflare/bootstrap.js" "$@"\n' \
            "${bash}/bin/bash" "${nodejs}/bin/node" "$NM" \
            > $out/bin/miniflare
          chmod +x $out/bin/miniflare
        '';
      }
    ];

    meta = {
      description = "Cloudflare wrangler + miniflare local Workers test tooling (vendored npm closure)";
      homepage = "https://miniflare.dev/";
      license = "MIT";
    };
  }
