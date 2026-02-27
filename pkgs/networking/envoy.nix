##! Envoy proxy — high-performance L7 proxy built from source
##!
##! Two-phase FOD build adapted from nixpkgs: (1) envoyDeps fetches all Bazel
##! external deps into a repository cache via `bazel sync --noenable_bzlmod`,
##! (2) the main build compiles envoy-static offline with --repository_disable_download.
##!
##! Store paths are scrubbed with per-tool placeholders (not a blanket regex) and
##! restored to actual paths before the build. This follows the nixpkgs pattern
##! for reproducible FOD hashes.
{
  mkDerivation,
  fetchurl,
  lib,
  bazel,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk,
  gcc,
  binutils,
  llvm,
  rust,
  cmake,
  ninja,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  ca-certificates,
  perl,
}:
let
  version = "1.37.0";

  # Configurable store directory (not hardcoded to /nix/store)
  storeDir = builtins.storeDir;

  # All tools Bazel needs in PATH during build
  toolsPath = lib.makeBinPath [
    bash
    coreutils
    which
    zip
    unzip
    gawk
    python3
    gcc
    binutils
    llvm
    rust
    cmake
    ninja
    grep
    gzip
    patch
    diffutils
    findutils
    sed
    tar
    xz
    file
    perl
  ];

  src = fetchurl {
    urls = [
      "https://github.com/envoyproxy/envoy/archive/v${version}.tar.gz"
    ];
    hash = lib.fakeHash;
  };

  # Common patch + setup script used in both FOD and build phases.
  # Applies patches, sets up Rust toolchain, injects Cargo/Rustc templates
  # into dependency_imports.bzl, and replaces shebangs.
  patchAndSetup = ''
    # Apply patches
    patch -p1 < ${./envoy-patches/0001-use-system-python.patch}
    patch -p1 < ${./envoy-patches/0003-use-system-cc-toolchains.patch}
    patch -p1 < ${./envoy-patches/0004-bump-rules-rust.patch}

    # Remove .bazelversion so AOS Bazel is used directly
    rm -f .bazelversion

    # Remove -Werror from envoy_internal.bzl (GCC may produce warnings Clang doesn't)
    sed -i '/"-Werror"/d' bazel/envoy_internal.bzl

    # Remove javabase from .bazelrc (we set it via --server_javabase)
    sed -i '/javabase=/d' .bazelrc

    # Set up Rust toolchain symlinks for Bazel
    # The nix-build.BUILD.bazel expects: cargo, rustc, rustdoc executables
    # and rustcroot/lib/rustlib/<triple>/lib/ for stdlib
    mkdir -p bazel/nix
    ln -sf ${rust}/bin/rustc bazel/nix/rustc
    ln -sf ${rust}/bin/cargo bazel/nix/cargo
    ln -sf ${rust}/bin/rustdoc bazel/nix/rustdoc
    ln -sf ${rust} bazel/nix/rustcroot
    # Substitute @bash@ placeholder in BUILD file
    sed "s|@bash@|${bash}/bin/bash|g" ${./envoy-patches/nix-build.BUILD.bazel} > bazel/nix/BUILD.bazel

    # Inject Rust toolchain templates into dependency_imports.bzl
    # Without this, Bazel's crate_universe can't find cargo/rustc
    sed -i \
      -e 's|crate_universe_dependencies()|crate_universe_dependencies(rust_toolchain_cargo_template="@@//bazel/nix:cargo", rust_toolchain_rustc_template="@@//bazel/nix:rustc")|' \
      -e 's|crates_repository(|crates_repository(rust_toolchain_cargo_template="@@//bazel/nix:cargo", rust_toolchain_rustc_template="@@//bazel/nix:rustc",|' \
      bazel/dependency_imports.bzl

    # Fix luajit build script shebang
    sed -i 's|#!/usr/bin/env python3|#!${python3}/bin/python3|' \
      bazel/foreign_cc/luajit.patch 2>/dev/null || true

    # Replace shebangs throughout the source tree
    find . -type f \( -name '*.sh' -o -name '*.bzl' -o -name 'BUILD' \
         -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name '*.py' \
         -o -name '*.tpl' \) | \
      while read f; do
        sed -i \
          -e "s|/usr/local/bin/bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/bash|${bash}/bin/bash|g" \
          -e "s|/bin/bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/env python3|${python3}/bin/python3|g" \
          -e "s|/usr/bin/env python|${python3}/bin/python3|g" \
          -e "s|/usr/bin/env bash|${bash}/bin/bash|g" \
          -e "s|/usr/bin/env|${coreutils}/bin/env|g" \
          -e "s|/bin/true|${coreutils}/bin/true|g" \
          "$f" 2>/dev/null || true
      done
  '';

  # Per-tool placeholder strings for store path scrubbing.
  # Each tool gets its own placeholder so we can restore the exact path
  # during the build phase (not a lossy blanket replacement).
  scrubPaths = ''
    # Targeted store path scrubbing — replace specific tool paths with
    # named placeholders so they can be restored to actual paths at build time.
    # This follows the nixpkgs pattern for reproducible FOD hashes.
    SCRUB_FILES=$(find "$out" -type f)
    for f in $SCRUB_FILES; do
      file "$f" | grep -q text || continue
      sed -i \
        -e "s|${python3}|__AOS_PYTHON__|g" \
        -e "s|${bash}|__AOS_BASH__|g" \
        -e "s|${coreutils}|__AOS_COREUTILS__|g" \
        -e "s|${rust}|__AOS_RUST__|g" \
        -e "s|${openjdk}|__AOS_JDK__|g" \
        -e "s|${gcc}|__AOS_GCC__|g" \
        -e "s|${binutils}|__AOS_BINUTILS__|g" \
        -e "s|${llvm}|__AOS_LLVM__|g" \
        "$f" 2>/dev/null || true
    done
  '';

  # Reverse the scrubbing — restore actual store paths from placeholders
  restorePaths = ''
    RESTORE_FILES=$(find ../repo_cache -type f)
    for f in $RESTORE_FILES; do
      file "$f" | grep -q text || continue
      sed -i \
        -e "s|__AOS_PYTHON__|${python3}|g" \
        -e "s|__AOS_BASH__|${bash}|g" \
        -e "s|__AOS_COREUTILS__|${coreutils}|g" \
        -e "s|__AOS_RUST__|${rust}|g" \
        -e "s|__AOS_JDK__|${openjdk}|g" \
        -e "s|__AOS_GCC__|${gcc}|g" \
        -e "s|__AOS_BINUTILS__|${binutils}|g" \
        -e "s|__AOS_LLVM__|${llvm}|g" \
        "$f" 2>/dev/null || true
    done
  '';

  # Fixed-output derivation: fetch all Bazel external dependencies into a
  # repository cache. Store paths are scrubbed with per-tool placeholders
  # so the output hash is stable across rebuilds.
  envoyDeps = builtins.derivation {
    name = "envoy-deps-${version}";
    system = lib.system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${toolsPath}:${openjdk}/bin:${bazel}/bin:$PATH"
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"
        export JAVA_HOME="${openjdk}"
        export SSL_CERT_FILE="${ca-certificates}/etc/ssl/certs/ca-certificates.crt"

        # Extract source
        mkdir -p "$TMPDIR/envoy_src"
        cd "$TMPDIR/envoy_src"
        tar xzf ${src} --strip-components=1

        ${patchAndSetup}

        # Fetch all external deps into repository cache
        bazel --batch \
          --output_user_root="$TMPDIR/bazel_cache" \
          --server_javabase="${openjdk}" \
          sync \
          --noenable_bzlmod \
          --repository_cache="$TMPDIR/repo_cache" \
          --curses=no \
          --verbose_failures || true

        # The bazel output_base contains the fetched external repos
        BAZEL_OUT="$TMPDIR/bazel_cache"
        EXTERNAL=$(find "$BAZEL_OUT" -type d -name external | head -1)

        # Copy repository cache to output
        cp -a "$TMPDIR/repo_cache" "$out" 2>/dev/null || mkdir -p "$out"

        # Save Cargo.Bazel.lock if it exists (pins Rust crate versions)
        if [ -n "$EXTERNAL" ] && [ -f "$EXTERNAL/../Cargo.Bazel.lock" ]; then
          cp "$EXTERNAL/../Cargo.Bazel.lock" "$out/Cargo.Bazel.lock"
        fi
        # Also check in the source tree
        if [ -f source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock ]; then
          cp source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock "$out/Cargo.Bazel.lock" 2>/dev/null || true
        fi

        # --- Clean non-reproducible artifacts ---

        # Remove compiled Python bytecode
        find "$out" -name "*.pyc" -type f -delete

        # Remove Go caches (timestamps, non-deterministic)
        find "$out" -type d -name "gocache" -exec rm -rf {} + 2>/dev/null || true
        find "$out" -type d -name "sumdb" -exec rm -rf {} + 2>/dev/null || true

        # Remove unused platform JDK downloads (keep only current platform)
        find "$out" -type d -name "remotejdk*" -exec rm -rf {} + 2>/dev/null || true
        find "$out" -type d -name "android*" -exec rm -rf {} + 2>/dev/null || true

        # Remove cargo_bazel_bootstrap and crate index caches
        find "$out" -type d -name "cargo_bazel_bootstrap" -exec rm -rf {} + 2>/dev/null || true
        find "$out" -type d -name ".cargo_home" -exec rm -rf {} + 2>/dev/null || true
        find "$out" -type d -name "splicing-output" -exec rm -rf {} + 2>/dev/null || true

        # --- Targeted store path scrubbing ---
        ${scrubPaths}

        # Normalize permissions for reproducibility
        find "$out" -type f -exec chmod 644 {} \;
        find "$out" -type d -exec chmod 755 {} \;
      ''
    ];

    outputHash = lib.fakeHash;
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };
in
mkDerivation {
  pname = "envoy";
  inherit version;

  inherit src;

  buildDeps = [
    bazel
    bash
    coreutils
    which
    zip
    unzip
    gawk
    python3
    openjdk
    gcc
    binutils
    llvm
    rust
    cmake
    ninja
    grep
    gzip
    patch
    diffutils
    findutils
    sed
    tar
    xz
    file
    ca-certificates
    perl
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir envoy_src
        cd envoy_src
        tar xzf $src --strip-components=1
      '';
    }
    {
      name = "patch";
      script = patchAndSetup;
    }
    {
      name = "build";
      script = ''
        # Copy repository cache from FOD and make writable
        cp -a ${envoyDeps} ../repo_cache
        chmod -R u+w ../repo_cache

        # Restore actual store paths from per-tool placeholders
        ${restorePaths}

        # Restore Cargo.Bazel.lock if it was saved
        if [ -f ../repo_cache/Cargo.Bazel.lock ]; then
          cp ../repo_cache/Cargo.Bazel.lock \
            source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock 2>/dev/null || true
        fi

        # Derive bootstrapTools lib path from CONFIG_SHELL (set by mkDerivation)
        BT_LIB=$(dirname "$(dirname "$CONFIG_SHELL")")/lib

        # Patch ELF binaries in the external repo cache so build tools
        # can execute with the correct dynamic linker
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        find ../repo_cache -type f -executable | while read execbin; do
          file "$execbin" | grep -q ': ELF .*, dynamically linked,' || continue
          patchelf --set-interpreter "$INTERP" "$execbin" 2>/dev/null || true
        done

        # tcmalloc fix for newer GCC: suppress -Wchanges-meaning
        find ../repo_cache -path "*/com_github_google_tcmalloc/tcmalloc/copts.bzl" | \
          while read f; do
            sed -i '/TCMALLOC_GCC_FLAGS = \[/a\    "-Wno-changes-meaning",' "$f" 2>/dev/null || true
          done

        # CMake 3.1 → 3.5 compatibility fix for libevent
        find ../repo_cache -path "*/com_github_libevent_libevent/CMakeLists.txt" | \
          while read f; do
            sed -i 's/cmake_minimum_required(VERSION 3\.1\b/cmake_minimum_required(VERSION 3.5/' "$f" 2>/dev/null || true
          done

        # Create bash wrapper with PATH for Bazel genrules (same pattern as bazel.nix)
        mkdir -p ../tools
        cat > ../tools/bash-with-path << BASHWRAP
        #!${bash}/bin/bash
        export PATH="${toolsPath}:\$PATH"
        export LD_LIBRARY_PATH="$BT_LIB''${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
        exec ${bash}/bin/bash "\$@"
        BASHWRAP
        chmod +x ../tools/bash-with-path

        export HOME=$(mktemp -d)
        export JAVA_HOME="${openjdk}"
        export SSL_CERT_FILE="${ca-certificates}/etc/ssl/certs/ca-certificates.crt"
        export PATH="${toolsPath}:$PATH"

        # Unset C_INCLUDE_PATH so Bazel's CC toolchain auto-detection doesn't
        # pick up bootstrapTools/include as a -I flag, which breaks
        # #include_next <stdlib.h> in the C++ standard library headers.
        unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH

        REPO_CACHE_ABS="$(cd ../repo_cache && pwd)"
        BASH_WITH_PATH="$(cd ../tools && pwd)/bash-with-path"

        bazel --batch \
          --output_user_root="$TMPDIR/bazel_cache" \
          --server_javabase="${openjdk}" \
          build -c opt //source/exe:envoy-static \
          --config=gcc \
          --spawn_strategy=standalone \
          --verbose_failures \
          --curses=no \
          --repository_cache="$REPO_CACHE_ABS" \
          --repository_disable_download \
          --noenable_bzlmod \
          --extra_toolchains=@local_jdk//:all \
          --java_runtime_version=local_jdk \
          --tool_java_runtime_version=local_jdk \
          --extra_toolchains=//bazel/nix:rust_nix_x86_64 \
          --linkopt=-fuse-ld=lld \
          --host_linkopt=-fuse-ld=lld \
          --linkopt=-Wl,-z,noexecstack \
          --linkopt=-Wl,--unresolved-symbols=ignore-in-object-files \
          --cxxopt=-Wno-changes-meaning \
          --action_env=PATH=${toolsPath} \
          --host_action_env=PATH=${toolsPath} \
          --action_env=LD_LIBRARY_PATH=$BT_LIB \
          --host_action_env=LD_LIBRARY_PATH=$BT_LIB \
          --shell_executable="$BASH_WITH_PATH" \
          --define=wasm=disabled \
          --incompatible_enable_cc_toolchain_resolution=true \
          --cxxopt=-Wno-error
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin

        ENVOY_BIN=bazel-bin/source/exe/envoy-static
        if [ ! -f "$ENVOY_BIN" ]; then
          echo "ERROR: bazel did not produce envoy-static binary" >&2
          exit 1
        fi

        cp "$ENVOY_BIN" $out/bin/envoy
        chmod +x $out/bin/envoy

        # Patch ELF interpreter and RPATH
        INTERP=$(patchelf --print-interpreter "$CONFIG_SHELL")
        BT_LIB=$(dirname "$INTERP")
        STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
        STDCXX_DIR=""
        if [ -n "$STDCXX_FILE" ]; then
          STDCXX_DIR=$(dirname "$STDCXX_FILE")
        fi
        RPATH="$BT_LIB"
        if [ -n "$STDCXX_DIR" ]; then
          RPATH="$RPATH:$STDCXX_DIR"
        fi
        patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" \
                 $out/bin/envoy 2>/dev/null || true
      '';
    }
  ];

  meta = {
    description = "Envoy proxy — high-performance L7 proxy and communication bus";
    homepage = "https://www.envoyproxy.io";
    license = "Apache-2.0";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkVMTest {
        name = "networking-envoy-version";
        rootfsDeps = [ self ];
        testScript = ''
          OUTPUT=$(envoy --version 2>&1)
          case "$OUTPUT" in
            *"1.37"*)
              echo "==> envoy version: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected envoy version: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };

      validate-config = testing.mkVMTest {
        name = "networking-envoy-validate-config";
        rootfsDeps = [ self ];
        testScript = ''
          # Write a minimal Envoy config
          mkdir -p /tmp/envoy
          cat > /tmp/envoy/config.yaml << 'YAML'
          static_resources:
            listeners:
            - name: test_listener
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 10000
              filter_chains:
              - filters:
                - name: envoy.filters.network.http_connection_manager
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    stat_prefix: ingress_http
                    route_config:
                      name: local_route
                      virtual_hosts:
                      - name: local_service
                        domains: ["*"]
                        routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: "hello"
                    http_filters:
                    - name: envoy.filters.http.router
                      typed_config:
                        "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          YAML

          envoy --mode validate -c /tmp/envoy/config.yaml 2>&1
          case "$?" in
            0)
              echo "==> envoy validate-config: PASS"
              ;;
            *)
              echo "==> ERROR: envoy config validation failed" >&2
              exit 1
              ;;
          esac
        '';
      };
    };
}
