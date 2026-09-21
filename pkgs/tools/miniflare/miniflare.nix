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
##! ## Cross builds
##!
##! The fixed npm tree is produced on Linux and therefore contains optional
##! Linux workerd, esbuild, and sharp/libvips binaries. Cross builds remove those
##! build-platform binaries. Their wrappers select source-built target `workerd` and
##! Go-built target esbuild through the tools' supported environment variables;
##! sharp retains its target-neutral WASM implementation. node-gyp itself runs
##! with native AOS Node/Python/make, while the ccWrapper and target Node headers
##! produce the target `better_sqlite3.node` addon. Darwin additionally models
##! the Xcode discovery queries required by gyp using the AOS SDK.
{
  mkDerivation,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  fetchNpmDeps,
  lib,
  stdenv,
  buildPackages,
  nodejs,
  python3,
  gnumake,
  bash,
  workerd,
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

  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  targetNodeArch =
    if stdenv.hostPlatform.darwinArch == "arm64" || stdenv.hostPlatform.system == "aarch64-linux"
    then "arm64"
    else "x64";
  targetMachArch =
    if targetNodeArch == "arm64"
    then "arm64"
    else "x86_64";

  # esbuild's JavaScript launcher honors ESBUILD_BINARY_PATH. Building the
  # small Go command directly avoids retaining its Linux npm platform package.
  esbuildVersion = "0.28.1";
  esbuildSrc = fetchurl {
    urls = [
      "https://github.com/evanw/esbuild/archive/refs/tags/v${esbuildVersion}.tar.gz"
    ];
    hash = "sha256-ZcdW+ofUMXisSlJCRUwr0P3jJfjs93mX+PpLiPlNXNI=";
  };
  targetEsbuild = mkGoPackage {
    pname = "esbuild";
    version = esbuildVersion;
    src = esbuildSrc;
    goModules = fetchGoModules {
      src = esbuildSrc;
      hash = "sha256-S2uhvYBwdLq6KEv59RmLqLgosbGxK1A6hMaVu6qnnfI=";
    };
    goPackage = "./cmd/esbuild";
    goOutput = "esbuild";
    doCheck = false;
    runtimeDeps = [];
    meta = {
      description = "JavaScript and CSS bundler used by Wrangler";
      homepage = "https://esbuild.github.io/";
      license = "MIT";
    };
  };
in
  mkDerivation {
    pname = "miniflare";
    inherit version;

    # No upstream source archive: the package content is the vendored
    # node_modules plus generated wrapper scripts.
    src = null;

    buildDeps =
      if isDarwinCross || isLinuxCross
      then [buildPackages.nodejs buildPackages.python3 buildPackages.gnumake buildPackages.file]
      else [nodejs python3 gnumake];
    runtimeDeps =
      [nodejs]
      ++ lib.optionals (isDarwinCross || isLinuxCross) [bash workerd targetEsbuild];

    phases = [
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out/lib $out/bin

            # The FOD is instantiated on Linux. Remove every optional ELF
            # platform package before the target closure is assembled. Sharp's
            # loader falls back to the installed sharp-wasm32 implementation.
            cp -a ${nodeModules} $out/lib/node_modules
            chmod -R u+w $out/lib/node_modules
            NM=$out/lib/node_modules

            # gyp's make-mac generator queries Xcode only for version and SDK
            # discovery. Model those read-only queries with the canonical AOS
            # SDK; compilation still goes through the Darwin ccWrapper.
            DARWIN_TOOLS=$TMPDIR/darwin-tools
            mkdir -p "$DARWIN_TOOLS"
            cat > "$DARWIN_TOOLS/xcodebuild" <<'XCODEBUILDEOF'
            #!${buildPackages.bash}/bin/bash
            case "$*" in
              -version)
                printf '%s\n' 'Xcode 16.0' 'Build version AOS'
                ;;
              -showsdks)
                printf '%s\n' 'macOS SDKs:' 'macOS ${stdenv.sdkVersion} -sdk macosx'
                ;;
              *)
                printf 'unsupported xcodebuild query:' >&2
                printf ' %s' "$@" >&2
                printf '\n' >&2
                exit 2
                ;;
            esac
            XCODEBUILDEOF
            cat > "$DARWIN_TOOLS/libtool" <<'LIBTOOLEOF'
            #!${buildPackages.bash}/bin/bash
            output=
            inputs=()
            while [ "$#" -gt 0 ]; do
              case "$1" in
                -static)
                  shift
                  ;;
                -o)
                  output=$2
                  shift 2
                  ;;
                *)
                  inputs+=("$1")
                  shift
                  ;;
              esac
            done
            if [ -z "$output" ]; then
              printf '%s\n' 'libtool: missing -o output' >&2
              exit 2
            fi
            exec ${stdenv.cc}/bin/ar crs "$output" "''${inputs[@]}"
            LIBTOOLEOF
            cat > "$DARWIN_TOOLS/xcrun" <<'XCRUNEOF'
            #!${buildPackages.bash}/bin/bash
            if [ "$1" = "--sdk" ]; then
              shift 2
            fi
            case "$1" in
              --show-sdk-path)
                printf '%s\n' '${stdenv.sdk}'
                ;;
              --show-sdk-version|--show-sdk-platform-version)
                printf '%s\n' '${stdenv.sdkVersion}'
                ;;
              --show-sdk-build-version)
                printf '%s\n' 'AOS'
                ;;
              --show-sdk-platform-path)
                printf '%s\n' '${stdenv.sdk}'
                ;;
              *)
                printf 'unsupported xcrun query:' >&2
                printf ' %s' "$@" >&2
                printf '\n' >&2
                exit 2
                ;;
            esac
            XCRUNEOF
            chmod +x \
              "$DARWIN_TOOLS/libtool" \
              "$DARWIN_TOOLS/xcodebuild" \
              "$DARWIN_TOOLS/xcrun"
            export PATH="$DARWIN_TOOLS:$PATH"

            rm -rf \
              "$NM"/@cloudflare/workerd-linux-* \
              "$NM"/wrangler/node_modules/@cloudflare/workerd-linux-* \
              "$NM"/@esbuild/linux-* \
              "$NM"/@img/sharp-linux-* \
              "$NM"/@img/sharp-linuxmusl-* \
              "$NM"/@img/sharp-libvips-linux-* \
              "$NM"/@img/sharp-libvips-linuxmusl-*
            test -d "$NM/@img/sharp-wasm32"

            # Run node-gyp on Linux but select Darwin's make flavor, target
            # architecture, compiler wrapper, Node headers, and libc++ flags.
            nodeGyp=${buildPackages.nodejs}/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js
            (
              cd "$NM/better-sqlite3"
              export npm_config_platform=darwin
              export npm_config_arch=${targetNodeArch}
              ${buildPackages.nodejs}/bin/node "$nodeGyp" rebuild \
                --release \
                --arch=${targetNodeArch} \
                --nodedir=${nodejs} \
                --python=${buildPackages.python3}/bin/python3 \
                -- \
                -f make-mac \
                -DOS=mac \
                -Dtarget_arch=${targetNodeArch} \
                -Dmac_deployment_target=${stdenv.deploymentTarget}
            )

            addon="$NM/better-sqlite3/build/Release/better_sqlite3.node"
            test -f "$addon"

            # Build metadata contains native tool paths but is not needed by
            # Node at runtime. Retain only the target addon in its canonical
            # lookup location.
            cp "$addon" "$TMPDIR/better_sqlite3.node"
            rm -rf "$NM/better-sqlite3/build"
            mkdir -p "$NM/better-sqlite3/build/Release"
            cp "$TMPDIR/better_sqlite3.node" "$addon"

            # Native addons are not covered by the generic `.so`/`.dylib`
            # scrub patterns. better-sqlite3 links system frameworks through
            # Node's dynamic module ABI, so no Nix store reference is needed.
            nuke-refs "$addon"

            # Fail closed if an optional package introduces another Linux
            # executable or native library in a future lockfile update.
            find "$NM" -type f -exec ${buildPackages.file}/bin/file {} + \
              > "$TMPDIR/npm-file-types"
            if grep -F 'ELF ' "$TMPDIR/npm-file-types"; then
              echo "ERROR: Linux ELF remains in Darwin miniflare closure" >&2
              exit 1
            fi
            grep -F 'Mach-O 64-bit ${targetMachArch}' "$TMPDIR/npm-file-types" \
              | grep -F 'better_sqlite3.node'

            # These are supported override hooks, so both Miniflare and
            # Wrangler execute source-built target tools instead of npm blobs.
            {
              printf '%s\n' '#!${bash}/bin/bash'
              printf '%s\n' 'export MINIFLARE_WORKERD_PATH="${workerd}/bin/workerd"'
              printf '%s\n' 'export ESBUILD_BINARY_PATH="${targetEsbuild}/bin/esbuild"'
              printf '%s\n' 'exec ${nodejs}/bin/node "'"$NM"'/wrangler/bin/wrangler.js" "$@"'
            } > $out/bin/wrangler
            chmod +x $out/bin/wrangler

            {
              printf '%s\n' '#!${bash}/bin/bash'
              printf '%s\n' 'export MINIFLARE_WORKERD_PATH="${workerd}/bin/workerd"'
              printf '%s\n' 'export ESBUILD_BINARY_PATH="${targetEsbuild}/bin/esbuild"'
              printf '%s\n' 'exec ${nodejs}/bin/node "'"$NM"'/miniflare/bootstrap.js" "$@"'
            } > $out/bin/miniflare
            chmod +x $out/bin/miniflare
          ''
          else if isLinuxCross
          then ''
            mkdir -p "$out/lib" "$out/bin"
            cp -a ${nodeModules} "$out/lib/node_modules"
            chmod -R u+w "$out/lib/node_modules"
            NM=$out/lib/node_modules

            # The vendored optional binaries belong to the build platform.
            # Select source-built target tools and Sharp's portable WASM backend.
            rm -rf \
              "$NM"/@cloudflare/workerd-linux-* \
              "$NM"/wrangler/node_modules/@cloudflare/workerd-linux-* \
              "$NM"/@esbuild/linux-* \
              "$NM"/@img/sharp-linux-* \
              "$NM"/@img/sharp-linuxmusl-* \
              "$NM"/@img/sharp-libvips-linux-* \
              "$NM"/@img/sharp-libvips-linuxmusl-*
            test -d "$NM/@img/sharp-wasm32"

            # Wrangler imports workerd's npm resolver before consulting
            # Miniflare's override. Give that resolver a source-built binary
            # in the target optional package's standard lookup location.
            workerd_package="$NM/@cloudflare/workerd-linux-${
              if targetNodeArch == "arm64"
              then "arm64"
              else "64"
            }"
            mkdir -p "$workerd_package/bin"
            ln -s ${workerd}/bin/workerd "$workerd_package/bin/workerd"

            nodeGyp=${buildPackages.nodejs}/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js
            (
              cd "$NM/better-sqlite3"
              export npm_config_platform=linux
              export npm_config_arch=${targetNodeArch}
              ${buildPackages.nodejs}/bin/node "$nodeGyp" rebuild \
                --release \
                --arch=${targetNodeArch} \
                --nodedir=${nodejs} \
                --python=${buildPackages.python3}/bin/python3
            )

            # Node only loads the addon. Generated makefiles and intermediates
            # retain build compiler paths and must not enter the runtime closure.
            addon="$NM/better-sqlite3/build/Release/better_sqlite3.node"
            cp "$addon" "$TMPDIR/better_sqlite3.node"
            rm -rf "$NM/better-sqlite3/build"
            mkdir -p "$NM/better-sqlite3/build/Release"
            cp "$TMPDIR/better_sqlite3.node" "$addon"

            # Native addons fall outside the generic shared-library scrub.
            # Keep their linked runtime libraries, but remove compiler-header
            # references embedded in C++ assertion diagnostics.
            set --
            for runtime_path in $(patchelf --print-rpath "$addon" | tr ':' ' '); do
              case "$runtime_path" in
                /nix/store/*) set -- "$@" -e "$runtime_path" ;;
              esac
            done
            nuke-refs "$@" "$addon"

            for command in wrangler miniflare; do
              case "$command" in
                wrangler) entry=wrangler/bin/wrangler.js ;;
                miniflare) entry=miniflare/bootstrap.js ;;
              esac
              {
                printf '%s\n' '#!${bash}/bin/bash'
                printf '%s\n' 'export MINIFLARE_WORKERD_PATH="${workerd}/bin/workerd"'
                printf '%s\n' 'export ESBUILD_BINARY_PATH="${targetEsbuild}/bin/esbuild"'
                printf 'exec %s "%s/%s" "$@"\n' '${nodejs}/bin/node' "$NM" "$entry"
              } > "$out/bin/$command"
              chmod +x "$out/bin/$command"
            done
          ''
          else ''
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

    passthru.evidenceSources = [
      ./miniflare.nix
      npmSrc
      esbuildSrc
    ];

    meta = {
      description = "Cloudflare wrangler + miniflare local Workers test tooling (vendored npm closure)";
      homepage = "https://miniflare.dev/";
      license = "MIT";
    };
  }
