# Building Envoy from Source in AOS

> **Status:** Proposal
>
> Envoy is a massive C++ project built with Bazel. Bazel requires a JDK.
> Neither Bazel, a JDK, nor Envoy exist in the AOS package set today.
> This document maps the full dependency chain, the nixpkgs reference
> implementations to base each package on, and the AOS-specific
> adaptations needed.

---

## Table of Contents

1. [Dependency Chain Overview](#1-dependency-chain-overview)
2. [Layer 0: OpenJDK (JDK 21 Headless)](#2-layer-0-openjdk-jdk-21-headless)
3. [Layer 1: Bazel 7](#3-layer-1-bazel-7)
4. [Layer 2: Envoy](#4-layer-2-envoy)
5. [Supporting Packages](#5-supporting-packages)
6. [AOS Build Infrastructure](#6-aos-build-infrastructure)
7. [Nixpkgs Reference Map](#7-nixpkgs-reference-map)
8. [Build Resources and Timing](#8-build-resources-and-timing)
9. [Implementation Order](#9-implementation-order)

---

## 1. Dependency Chain Overview

```
envoy (C++, ~100 MB binary)
  |
  +-- bazel_7 (Java + native, ~200 MB)
  |     |
  |     +-- openjdk21-headless (build + run JDK)
  |     |     |
  |     |     +-- openjdk21-bootstrap (prebuilt binary, to compile JDK 21)
  |     |     +-- OR: openjdk17 -> openjdk11 -> ... (from-source chain)
  |     |     +-- build deps: make, autoconf, bash, zip, unzip,
  |     |     |   coreutils, which, gawk, sed, tar, grep, gzip, findutils
  |     |     +-- optional headless deps: cups (stubbed), freetype,
  |     |         alsa-lib (stubbed), fontconfig (stubbed)
  |     |
  |     +-- python3 (already in AOS)
  |     +-- zip, unzip
  |     +-- bash, coreutils, which, gawk, sed, tar, grep, gzip, findutils
  |     +-- bazel-deps FOD (~16 GB vendored deps)
  |
  +-- containerd external deps (via Bazel FOD):
  |     +-- boringssl, abseil-cpp, protobuf, grpc, c-ares, re2,
  |     +-- nghttp2, libevent, yaml-cpp, xxhash, zlib, brotli,
  |     +-- fmt, spdlog, tclap, http-parser, wasm runtimes, ...
  |
  +-- build-time native deps:
  |     +-- cmake (already in AOS)
  |     +-- ninja (already in AOS)
  |     +-- python3 (already in AOS)
  |     +-- cargo + rustc (already in AOS)
  |     +-- gn (new - Generate Ninja)
  |     +-- patchelf (already in AOS)
  |
  +-- openjdk11-headless (Envoy build uses JDK 11 for Java code gen)
```

### What Already Exists in AOS

| Package | Status | Path |
|---------|--------|------|
| cmake | Built | `pkgs/build-systems/cmake.nix` |
| ninja | Built | `pkgs/build-systems/ninja.nix` |
| python3 | Built | `pkgs/interpreters/python3.nix` |
| cargo + rustc | Built | `pkgs/toolchain/rust.nix` |
| make | Built | `pkgs/build-systems/make.nix` |
| autoconf | Built | `pkgs/build-systems/autoconf.nix` |
| patchelf | Built | `pkgs/core/patchelf.nix` (bootstrap) |
| bash | Built | `pkgs/core/bash.nix` |
| coreutils | Built | `pkgs/core/coreutils.nix` |
| tar | Built | `pkgs/core/tar.nix` |
| gawk | Built | `pkgs/core/gawk.nix` |
| sed | Built | `pkgs/core/sed.nix` |
| grep | Built | `pkgs/core/grep.nix` |
| gzip | Built | `pkgs/compression/gzip.nix` |
| findutils | Built | `pkgs/core/findutils.nix` |
| zlib | Built | `pkgs/compression/zlib.nix` |
| openssl | Built | `pkgs/tls/openssl.nix` |

### What Needs to Be Built (New Packages)

| Package | Complexity | Nixpkgs Reference |
|---------|-----------|-------------------|
| openjdk21-bootstrap | Trivial (prebuilt binary) | `pkgs/by-name/ba/bazel_7/package.nix` (bazelBootstrap pattern) |
| openjdk21-headless | High | `pkgs/development/compilers/openjdk/21/` |
| openjdk11-headless | High | `pkgs/development/compilers/openjdk/11/` |
| zip | Low | `pkgs/by-name/zi/zip/` |
| unzip | Low | `pkgs/by-name/un/unzip/` |
| which | Trivial | `pkgs/by-name/wh/which/` |
| bazel_7 | Very High | `pkgs/by-name/ba/bazel_7/package.nix` |
| gn | Medium | `pkgs/by-name/gn/gn/` |
| envoy | Very High | `pkgs/by-name/en/envoy/package.nix` |

---

## 2. Layer 0: OpenJDK (JDK 21 Headless)

### 2.1 Bootstrap Strategy

Bazel 7 requires JDK 21 to build and run. OpenJDK requires a JDK to
compile (chicken-and-egg). Two options:

**Option A: Binary bootstrap (recommended, matches nixpkgs)**

Download a prebuilt JDK 21 binary (Adoptium/Temurin), use it as the
boot JDK to compile OpenJDK 21 from source. The result is a
from-source JDK; the bootstrap binary is build-time only.

```nix
# pkgs/toolchain/openjdk21-bootstrap.nix
{ mkDerivation, fetchurl }:
let
  version = "21.0.6+7";
  arch = "x64";  # or "aarch64"
in
mkDerivation {
  pname = "openjdk21-bootstrap";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-${version}/OpenJDK21U-jdk_${arch}_linux_hotspot_21.0.6_7.tar.gz"
    ];
    hash = "sha256-...";  # Use `aos prefetch` to get hash
  };

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out
        cp -a jdk-*/* $out/

        # Patch ELF interpreter and RPATH for Nix store
        for f in $(find $out -type f -executable); do
          if file "$f" | grep -q ELF; then
            patchelf --set-interpreter \
              ${bootstrapTools}/lib/ld-linux-x86-64.so.2 "$f" 2>/dev/null || true
            patchelf --set-rpath \
              "$out/lib:$out/lib/server:${bootstrapTools}/lib" "$f" 2>/dev/null || true
          fi
        done
      '';
    }
  ];
}
```

**Option B: Full from-source bootstrap (Guix approach)**

Build chain: Jikes (C++) -> GNU Classpath 0.93 -> JamVM -> Ant ->
ECJ -> GNU Classpath 0.99 -> JamVM -> OpenJDK 6 -> OpenJDK 7 ->
OpenJDK 8 -> ... -> OpenJDK 21. This is ~10 packages and much more
work. Only needed if the project requires zero binary bootstrap.

**Recommendation**: Option A. The bootstrap binary is a build dep
only, not shipped in the golden image. This matches nixpkgs practice.

### 2.2 OpenJDK 21 Headless (From Source)

**Nixpkgs reference**: `pkgs/development/compilers/openjdk/21/default.nix`

Key points from nixpkgs:
- Uses `--with-boot-jdk` pointing to boot JDK (N-1 or same version)
- `--enable-headless-only` eliminates all X11/AWT/Swing dependencies
- `--with-native-debug-symbols=none` reduces size
- Result is ~200-300 MB, headless cuts it to ~150 MB

```nix
# pkgs/toolchain/openjdk21.nix
{ mkDerivation, fetchurl, make, autoconf, bash, zip, unzip,
  which, gawk, coreutils, openjdk21-bootstrap,
  # Headless deps
  zlib, freetype, ... }:
let
  version = "21.0.6";
  update = "7";
in
mkDerivation {
  pname = "openjdk21-headless";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/openjdk/jdk21u/archive/refs/tags/jdk-${version}+${update}.tar.gz"
    ];
    hash = "sha256-...";
  };

  buildDeps = [ make autoconf bash zip unzip which gawk coreutils ];
  runtimeDeps = [ zlib ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jdk21u-*
      '';
    }
    {
      name = "configure";
      script = ''
        # Reference: nixpkgs openjdk21/default.nix configureFlags
        bash configure \
          --with-boot-jdk=${openjdk21-bootstrap} \
          --prefix=$out \
          --enable-headless-only \
          --with-native-debug-symbols=none \
          --with-zlib=system \
          --with-stdc++lib=dynamic \
          --disable-warnings-as-errors \
          --disable-precompiled-headers \
          --with-extra-cflags="$NIX_CFLAGS_COMPILE" \
          --with-extra-ldflags="$NIX_LDFLAGS" \
          --with-extra-cxxflags="$NIX_CFLAGS_COMPILE"
      '';
    }
    {
      name = "build";
      script = ''
        make images JOBS=$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        cp -a build/*/images/jdk/* $out/
      '';
    }
  ];
}
```

**Critical nixpkgs patches to review**:
- `fix-java-home.patch` - Fixes JAVA_HOME detection
- `read-truststore-from-env-var.patch` - CA certs from env
- `openjdk-currency-date-range.patch` - Date handling fix
- Check `pkgs/development/compilers/openjdk/21/` for current patch list

### 2.3 OpenJDK 11 Headless (For Envoy)

Same pattern as JDK 21 but uses `openjdk21-headless` as boot JDK
(JDK N+1 can boot JDK N). Or build JDK 17 first, then JDK 11.
Nixpkgs uses the approach of bootstrapping from a newer JDK.

**Nixpkgs reference**: `pkgs/development/compilers/openjdk/11/default.nix`

---

## 3. Layer 1: Bazel 7

### 3.1 Build Strategy

Bazel is a Java application that requires itself to build. Nixpkgs
solves this with a **3-stage approach**:

1. **Stage 0 (bazelBootstrap)**: Download prebuilt Bazel binary
2. **Stage 1 (bazelDeps FOD)**: Use bootstrap Bazel to vendor all
   external dependencies into a fixed-output derivation (~16 GB)
3. **Stage 2 (bazel)**: Build Bazel from source using vendored deps
   and `--repository_disable_download`

### 3.2 Stage 0: Bootstrap Bazel Binary

```nix
# pkgs/build-systems/bazel-bootstrap.nix
{ mkDerivation, fetchurl, bash, coreutils, which, gawk, sed, tar, grep,
  gzip, findutils, python3, zip, unzip, openjdk21-headless }:
mkDerivation {
  pname = "bazel-bootstrap";
  version = "7.6.0";

  # Prebuilt binary for bootstrap only
  src = fetchurl {
    urls = [
      # Reference: nixpkgs bazel_7/package.nix bazelBootstrap
      "https://github.com/bazelbuild/bazel/releases/download/7.6.0/bazel_nojdk-7.6.0-linux-x86_64"
    ];
    hash = "sha256-94KFvsS7fInXFTQZPzMq6DxnHQrRktljwACyAz8adSw=";
  };

  buildDeps = [];
  runtimeDeps = [ openjdk21-headless ];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -Dm755 $src $out/bin/bazel

        # Patch ELF for Nix store
        patchelf --set-interpreter \
          ${bootstrapTools}/lib/ld-linux-x86-64.so.2 $out/bin/bazel

        # Wrap with PATH containing required tools
        mv $out/bin/bazel $out/bin/.bazel-unwrapped
        cat > $out/bin/bazel << 'EOF'
        #!/bin/sh
        export PATH="${bash}/bin:${coreutils}/bin:${which}/bin:${gawk}/bin:${sed}/bin:${tar}/bin:${grep}/bin:${gzip}/bin:${findutils}/bin:${python3}/bin:${zip}/bin:${unzip}/bin''${PATH:+:$PATH}"
        export JAVA_HOME="${openjdk21-headless}"
        exec "$(dirname "$0")/.bazel-unwrapped" "$@"
        EOF
        chmod +x $out/bin/bazel
      '';
    }
  ];
}
```

### 3.3 Stage 1: Vendored Dependencies (FOD)

This is the critical piece. Bazel downloads hundreds of external
dependencies at build time. To make this hermetic, we create a
**fixed-output derivation** (FOD) that:

1. Runs `bazel vendor` with network access (FODs are allowed internet)
2. Captures all downloaded deps into a content-hashed output
3. The hash is committed to the package definition

```nix
# pkgs/build-systems/bazel-deps.nix
{ mkDerivation, fetchurl, unzip, openjdk21-headless, bazel-bootstrap }:
let
  version = "7.6.0";
  src = fetchurl {
    urls = [
      "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel-${version}-dist.zip"
    ];
    hash = "sha256-eQKNB38G8ziDuorzoj5Rne/DZQL22meVLrdK0z7B2FI=";
  };
in
# This derivation uses builtins.derivation directly because it needs
# to be a fixed-output derivation with network access.
builtins.derivation {
  name = "bazel-${version}-deps";
  system = "x86_64-linux";
  builder = "${bash}/bin/bash";

  # FOD attributes: allow network, verify hash
  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = "sha256-yKy6IBIkjvN413kFMgkWCH3jAgF5AdpxrVnQyhgfWPA=";
  # ^^^ Platform-specific. Get from nixpkgs or compute.

  args = [ "-c" ''
    export PATH="${unzip}/bin:${openjdk21-headless}/bin:${bazel-bootstrap}/bin:$PATH"
    export HOME=$(mktemp -d)
    export JAVA_HOME="${openjdk21-headless}"

    # Unpack Bazel source
    mkdir src && cd src
    unzip ${src}

    # Use Bazel vendor mode to download all deps
    # Reference: nixpkgs bazel_7/package.nix bazelDeps
    mkdir ../vendor_dir
    bazel --server_javabase=${openjdk21-headless} vendor src:bazel_nojdk \
      --vendor_dir ../vendor_dir \
      --tool_java_runtime_version=local_jdk_21 \
      --java_runtime_version=local_jdk_21

    # Clean non-reproducible artifacts
    # Reference: nixpkgs bazel_7/package.nix bazelDeps buildPhase
    rm -rf ../vendor_dir/gazelle~~non_module_deps~bazel_gazelle_go_repository_cache/gocache
    rm -f ../vendor_dir/rules_go~~go_sdk~go_default_sdk/versions.json
    find ../vendor_dir -name "*.pyc" -type f -delete
    rm -f ../vendor_dir/bazel-external

    # Install
    mkdir -p $out/vendor_dir
    cp -r ../vendor_dir/* $out/vendor_dir/
  '' ];
}
```

**Getting the hash**: Build with a dummy hash first, Nix will fail
and report the actual hash. Or copy from nixpkgs for the same Bazel
version/platform.

### 3.4 Stage 2: Build Bazel from Source

```nix
# pkgs/build-systems/bazel.nix
{ mkDerivation, fetchurl, bash, coreutils, which, gawk, sed, tar, grep,
  gzip, findutils, python3, zip, unzip, make,
  openjdk21-headless, bazel-deps, lndir }:
let
  version = "7.6.0";
in
mkDerivation {
  pname = "bazel";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel-${version}-dist.zip"
    ];
    hash = "sha256-eQKNB38G8ziDuorzoj5Rne/DZQL22meVLrdK0z7B2FI=";
  };

  buildDeps = [
    bash coreutils which gawk sed tar grep gzip findutils
    python3 zip unzip make lndir openjdk21-headless
  ];

  # requiredSystemFeatures = [ "big-parallel" ];

  phases = [
    {
      name = "unpack";
      script = ''
        unzip $src -d bazel_src
      '';
    }
    {
      name = "patch";
      script = ''
        cd bazel_src

        # Reference: nixpkgs bazel_7/package.nix postPatch (genericPatches)
        # Replace hardcoded /bin/ paths with Nix store paths
        grep -rlZ /bin/ \
          src/main/java/com/google/devtools/\
          tools \
        | while IFS="" read -r -d "" path; do
          sed -i \
            -e "s!/usr/local/bin/bash!${bash}/bin/bash!g" \
            -e "s!/usr/bin/bash!${bash}/bin/bash!g" \
            -e "s!/bin/bash!${bash}/bin/bash!g" \
            -e "s!/usr/bin/env bash!${bash}/bin/bash!g" \
            -e "s!/usr/bin/env python!${python3}/bin/python3!g" \
            -e "s!/usr/bin/env!${coreutils}/bin/env!g" \
            -e "s!/bin/true!${coreutils}/bin/true!g" \
            "$path"
        done

        # Replace hardcoded action env PATH
        # Reference: nixpkgs strict_action_env.patch
        local defaultShellPath="${bash}/bin:${coreutils}/bin:${which}/bin:${gawk}/bin:${sed}/bin:${tar}/bin:${grep}/bin:${gzip}/bin:${findutils}/bin:${python3}/bin:${zip}/bin:${unzip}/bin"
        sed -i "s|/bin:/usr/bin:/usr/local/bin|$defaultShellPath|g" \
          src/main/java/com/google/devtools/build/lib/bazel/rules/BazelRuleClassProvider.java

        # Fix compile.sh to use vendored deps and local JDK
        # Reference: nixpkgs bazel_7/package.nix postPatch (sedVerbose compile.sh)
        sed -i \
          -e "/bazel_build /a\\  --verbose_failures \\\\" \
          -e "/bazel_build /a\\  --tool_java_runtime_version=local_jdk_21 \\\\" \
          -e "/bazel_build /a\\  --java_runtime_version=local_jdk_21 \\\\" \
          -e "/bazel_build /a\\  --extra_toolchains=@bazel_tools//tools/jdk:all \\\\" \
          -e "/bazel_build /a\\  --vendor_dir=../vendor_dir \\\\" \
          -e "/bazel_build /a\\  --repository_disable_download \\\\" \
          compile.sh

        cd ..
      '';
    }
    {
      name = "setup-vendor";
      script = ''
        # Symlink vendored deps from the FOD
        # Reference: nixpkgs bazel_7/package.nix preBuildPhase
        mkdir vendor_dir
        ${lndir}/bin/lndir ${bazel-deps}/vendor_dir vendor_dir
        rm -f vendor_dir/VENDOR.bazel
        find vendor_dir -maxdepth 1 -type d -printf "pin(\"@@%P\")\n" > vendor_dir/VENDOR.bazel
      '';
    }
    {
      name = "build";
      script = ''
        export HOME=$(mktemp -d)
        export JAVA_HOME="${openjdk21-headless}"
        export EMBED_LABEL="${version}- (@non-git)"

        cd bazel_src
        ${bash}/bin/bash ./compile.sh
        cd ..
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cp bazel_src/output/bazel $out/bin/bazel-${version}-linux-x86_64

        # Create wrapper script
        # Reference: nixpkgs bazel_7/package.nix installPhase
        local defaultShellPath="${bash}/bin:${coreutils}/bin:${which}/bin:${gawk}/bin:${sed}/bin:${tar}/bin:${grep}/bin:${gzip}/bin:${findutils}/bin:${python3}/bin:${zip}/bin:${unzip}/bin"
        cat > $out/bin/bazel << EOF
        #!/bin/sh
        export PATH="\$PATH:$defaultShellPath"
        exec "$out/bin/bazel-${version}-linux-x86_64" "\$@"
        EOF
        chmod +x $out/bin/bazel
      '';
    }
  ];

  # Reference: nixpkgs patches to apply
  # - java_toolchain.patch (nonprebuilt local JDK toolchain)
  # - strict_action_env.patch (Nix store PATH)
  # - bazel_rc.patch (system bazelrc pointing to local JDK)
  # See section 7 for full patch list
}
```

---

## 4. Layer 2: Envoy

### 4.1 Two-Phase Build (buildBazelPackage pattern)

Envoy uses Bazel and downloads hundreds of C++ dependencies at build
time. The nixpkgs `buildBazelPackage` pattern solves this with two
derivations:

**Phase 1 (fetchAttrs)**: A FOD that runs `bazel build --nobuild` to
fetch all external deps, then tars them into a hash-verified archive.

**Phase 2 (buildAttrs)**: Unpacks the fetched deps, sets
`--repository_disable_download`, and runs the real build.

### 4.2 Envoy Dependency Fetch (FOD)

```nix
# pkgs/networking/envoy-deps.nix
# Reference: nixpkgs envoy/package.nix fetchAttrs
{ mkDerivation, fetchurl, bazel, openjdk11-headless, python3,
  cmake, ninja, cargo, rustc, git, cacert }:
let
  version = "1.36.2";
  src = fetchurl {
    urls = [
      "https://github.com/envoyproxy/envoy/archive/v${version}.tar.gz"
    ];
    hash = "sha256-...";
  };
in
builtins.derivation {
  name = "envoy-${version}-deps.tar.gz";
  system = "x86_64-linux";
  builder = "${bash}/bin/bash";

  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = "sha256-...";  # From nixpkgs or computed

  args = [ "-c" ''
    export PATH="${bazel}/bin:${python3}/bin:${cmake}/bin:${ninja}/bin:${cargo}/bin:${rustc}/bin:${git}/bin:$PATH"
    export HOME="$NIX_BUILD_TOP"
    export JAVA_HOME="${openjdk11-headless}"
    export GIT_SSL_CAINFO="${cacert}/etc/ssl/certs/ca-bundle.crt"
    export SSL_CERT_FILE="${cacert}/etc/ssl/certs/ca-bundle.crt"

    bazelOut="$NIX_BUILD_TOP/output"
    bazelUserRoot="$NIX_BUILD_TOP/tmp"
    mkdir -p "$bazelOut" "$bazelUserRoot"

    tar xf ${src}
    cd envoy-${version}

    # Apply patches (see section 4.4)

    # Fetch deps using --nobuild
    # Reference: nixpkgs buildBazelPackage fetchAttrs.buildPhase
    BAZEL_USE_CPP_ONLY_TOOLCHAIN=1 \
    USER=homeless-shelter \
    bazel \
      --batch \
      --output_base="$bazelOut" \
      --output_user_root="$bazelUserRoot" \
      build --nobuild \
      --loading_phase_threads=1 \
      //source/exe:envoy-static

    # Populate repository cache
    bazel sync --noenable_bzlmod \
      --repository_cache="$bazelOut/external/repository_cache"

    # Clean non-reproducible artifacts
    # Reference: nixpkgs envoy/package.nix fetchAttrs.preInstall
    rm -rf $bazelOut/external/remotejdk*
    rm -rf $bazelOut/external/android_tools

    # Remove built-in workspaces Bazel will recreate
    rm -rf $bazelOut/external/{bazel_tools,@bazel_tools.marker}
    rm -rf $bazelOut/external/{embedded_jdk,@embedded_jdk.marker}

    # Tar up the result
    (cd $bazelOut/ && tar czf $out --sort=name --mtime='@1' \
     --owner=0 --group=0 --numeric-owner external/)
  '' ];
}
```

### 4.3 Envoy Build

```nix
# pkgs/networking/envoy.nix
# Reference: nixpkgs envoy/package.nix
{ mkDerivation, fetchurl, bazel, openjdk11-headless, python3,
  cmake, ninja, cargo, rustc, patchelf, envoy-deps, linuxHeaders }:
let
  version = "1.36.2";
in
mkDerivation {
  pname = "envoy";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/envoyproxy/envoy/archive/v${version}.tar.gz"
    ];
    hash = "sha256-...";
  };

  buildDeps = [
    bazel openjdk11-headless python3 cmake ninja cargo rustc patchelf
  ];
  runtimeDeps = [ linuxHeaders ];

  # requiredSystemFeatures = [ "big-parallel" ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd envoy-${version}
      '';
    }
    {
      name = "patch";
      script = ''
        # Apply AOS-specific patches (see section 4.4)

        # Set up Rust toolchain symlinks
        # Reference: nixpkgs envoy/package.nix postPatch
        mkdir -p bazel/nix/
        ln -sf "${cargo}/bin/cargo" bazel/nix/cargo
        ln -sf "${rustc}/bin/rustc" bazel/nix/rustc
        ln -sf "${rustc}/bin/rustdoc" bazel/nix/rustdoc
      '';
    }
    {
      name = "setup-deps";
      script = ''
        # Unpack pre-fetched dependencies
        # Reference: nixpkgs buildBazelPackage preConfigure
        bazelOut="$NIX_BUILD_TOP/output"
        mkdir -p "$bazelOut"
        (cd "$bazelOut" && tar xfz ${envoy-deps})
        chmod -R +w "$bazelOut"

        # Configure Bazel to use pre-fetched deps
        echo 'common --repository_cache="'"$bazelOut"'/external/repository_cache"' >> .bazelrc
        echo 'common --repository_disable_download' >> .bazelrc
      '';
    }
    {
      name = "build";
      script = ''
        export HOME="$NIX_BUILD_TOP"
        export JAVA_HOME="${openjdk11-headless}"

        bazelOut="$NIX_BUILD_TOP/output"
        bazelUserRoot="$NIX_BUILD_TOP/tmp"

        # Build flags from nixpkgs envoy/package.nix
        BAZEL_USE_CPP_ONLY_TOOLCHAIN=1 \
        USER=homeless-shelter \
        bazel \
          --batch \
          --output_base="$bazelOut" \
          --output_user_root="$bazelUserRoot" \
          build \
          -c opt \
          --spawn_strategy=standalone \
          --noexperimental_strict_action_env \
          --config=gcc \
          --verbose_failures \
          --extra_toolchains=@local_jdk//:all \
          --java_runtime_version=local_jdk \
          --tool_java_runtime_version=local_jdk \
          --jobs $NIX_BUILD_CORES \
          //source/exe:envoy-static
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cp bazel-bin/source/exe/envoy-static $out/bin/envoy
        patchelf --set-rpath "${bootstrapTools}/lib" $out/bin/envoy
      '';
    }
  ];
}
```

### 4.4 Required Patches (From Nixpkgs)

Nixpkgs applies 3 critical patches to Envoy. These must be adapted
for AOS:

**1. `0001-nixpkgs-use-system-Python.patch`**
- Removes `python_register_toolchains()` (prevents Bazel downloading Python)
- Configures `pip_parse()` to use system Python
- **Nixpkgs source**: `pkgs/by-name/en/envoy/0001-nixpkgs-use-system-Python.patch`

**2. `0003-nixpkgs-use-system-C-C-toolchains.patch`**
- Sets `register_default_tools=False, register_built_tools=False,
  register_preinstalled_tools=True` in `rules_foreign_cc_dependencies()`
- Forces use of system GCC instead of Bazel's downloaded toolchains
- **Nixpkgs source**: `pkgs/by-name/en/envoy/0003-nixpkgs-use-system-C-C-toolchains.patch`

**3. `0004-nixpkgs-bump-rules_rust-to-0.60.0.patch`**
- Updates Rust rules for compatibility with system Rust
- **Nixpkgs source**: `pkgs/by-name/en/envoy/0004-nixpkgs-bump-rules_rust-to-0.60.0.patch`

**How to pull patches**: Download from the nixpkgs repo at the
appropriate commit and place in `pkgs/networking/envoy-patches/`.

---

## 5. Supporting Packages

### 5.1 zip and unzip

Simple autoconf builds. Needed by Bazel for .jar manipulation.

```nix
# pkgs/compression/zip.nix
{ mkDerivation, fetchurl, make }:
let version = "3.0"; in
mkDerivation {
  pname = "zip"; inherit version;
  src = fetchurl { urls = [ "..." ]; hash = "sha256-..."; };
  buildDeps = [ make ];
  phases = [
    { name = "unpack"; script = "tar xf $src && cd zip30"; }
    { name = "build"; script = "make -f unix/Makefile generic_gcc"; }
    { name = "install"; script = "make -f unix/Makefile prefix=$out install"; }
  ];
}
```

### 5.2 which

Trivial autoconf package (~20 KB). Already common in most systems.

### 5.3 gn (Generate Ninja)

Used by some Envoy deps (e.g., boringssl). Built from source with
a simple Python bootstrap script.

```nix
# pkgs/build-systems/gn.nix
{ mkDerivation, fetchurl, python3, ninja }:
mkDerivation {
  pname = "gn"; version = "...";
  buildDeps = [ python3 ninja ];
  phases = [
    { name = "build"; script = "python3 build/gen.py && ninja -C out"; }
    { name = "install"; script = "install -Dm755 out/gn $out/bin/gn"; }
  ];
}
```

### 5.4 lndir

Used by Bazel build to symlink vendored deps. Part of X11 utils in
nixpkgs. Can be built standalone or replaced with a shell script:

```sh
# lndir replacement
for f in "$1"/*; do ln -s "$f" "$2/$(basename "$f")"; done
```

---

## 6. AOS Build Infrastructure

### 6.1 buildBazelPackage Helper

Create an AOS equivalent of nixpkgs `buildBazelPackage` at
`lib/bazel.nix`:

```nix
# lib/bazel.nix
{ mkDerivation, bazel, bash, coreutils, cacert }:
{
  buildBazelPackage = args@{
    name ? "${args.pname}-${args.version}",
    fetchAttrs,     # FOD config (hash, preInstall, etc.)
    buildAttrs,     # Build config (bazelBuildFlags, etc.)
    bazelTargets,   # List of Bazel targets to build
    ...
  }:
  let
    deps = builtins.derivation {
      name = "${name}-deps.tar.gz";
      system = "x86_64-linux";
      builder = "${bash}/bin/bash";
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
      inherit (fetchAttrs) outputHash;
      args = [ "-c" fetchAttrs.script ];
    };
  in
  mkDerivation (buildAttrs // {
    inherit name;
    preConfigure = ''
      mkdir -p "$NIX_BUILD_TOP/output"
      (cd "$NIX_BUILD_TOP/output" && tar xfz ${deps})
      chmod -R +w "$NIX_BUILD_TOP/output"
      ${buildAttrs.preConfigure or ""}
    '';
  });
}
```

### 6.2 Fixed-Output Derivation Support

AOS's `fetchurl` already uses `builtins.derivation` with
`outputHash`. The Bazel deps FOD follows the same pattern but with
`outputHashMode = "recursive"` (directory hash instead of file hash).

Ensure `lib/derivations.nix` supports FODs with recursive hash mode.
This may already work via `builtins.derivation` directly.

---

## 7. Nixpkgs Reference Map

For each new package, the nixpkgs files to pull patches and build
scripts from:

| AOS Package | Nixpkgs Path | What to Reference |
|------------|-------------|-------------------|
| openjdk21-bootstrap | `pkgs/by-name/ba/bazel_7/package.nix` (bazelBootstrap) | Binary fetch + patchelf pattern |
| openjdk21-headless | `pkgs/development/compilers/openjdk/21/default.nix` | Configure flags, patches, headless build |
| openjdk11-headless | `pkgs/development/compilers/openjdk/11/default.nix` | Configure flags, patches |
| bazel-bootstrap | `pkgs/by-name/ba/bazel_7/package.nix` (bazelBootstrap) | Binary download, wrapper |
| bazel-deps | `pkgs/by-name/ba/bazel_7/package.nix` (bazelDeps) | Vendor mode, FOD hash, cleanup |
| bazel | `pkgs/by-name/ba/bazel_7/package.nix` (main derivation) | Patches, compile.sh modifications, wrapper |
| envoy-deps | `pkgs/by-name/en/envoy/package.nix` (fetchAttrs) | FOD build, repository cache, cleanup |
| envoy | `pkgs/by-name/en/envoy/package.nix` (buildAttrs) | Build flags, Rust toolchain, patches |
| gn | `pkgs/by-name/gn/gn/package.nix` | Build script, Python bootstrap |
| zip | `pkgs/by-name/zi/zip/package.nix` | Makefile invocation |
| unzip | `pkgs/by-name/un/unzip/package.nix` | Makefile, patches |

### Patches to Pull from Nixpkgs

**Bazel patches** (from `pkgs/by-name/ba/bazel_7/`):
- `java_toolchain.patch` - Non-prebuilt local JDK toolchain
- `strict_action_env.patch` - Replace `/bin:/usr/bin` with Nix paths
- `bazel_rc.patch` - System bazelrc pointing to local JDK
- `darwin_sleep.patch` - (skip, Linux only)
- `trim-last-argument-to-gcc-if-empty.patch` - GCC arg fix
- `nix-build-bazel-package-hacks.patch` - enableNixHacks mode

**Envoy patches** (from `pkgs/by-name/en/envoy/`):
- `0001-nixpkgs-use-system-Python.patch`
- `0003-nixpkgs-use-system-C-C-toolchains.patch`
- `0004-nixpkgs-bump-rules_rust-to-0.60.0.patch`

**OpenJDK patches** (from `pkgs/development/compilers/openjdk/21/`):
- Check the current patch list at the time of implementation
- Common: `fix-java-home.patch`, `read-truststore-from-env-var.patch`

---

## 8. Build Resources and Timing

| Package | Disk Space | RAM | CPU Time (est.) |
|---------|-----------|-----|-----------------|
| openjdk21-headless | ~2 GB | 4 GB | 20-40 min |
| openjdk11-headless | ~2 GB | 4 GB | 20-40 min |
| bazel-deps (FOD) | ~16 GB | 4 GB | 10-20 min (download) |
| bazel (from source) | ~4 GB | 8 GB | 30-60 min |
| envoy-deps (FOD) | ~8 GB | 4 GB | 10-20 min (download) |
| envoy (from source) | ~5 GB | 16 GB | 60-120 min |
| **Total** | **~37 GB** | **16 GB peak** | **~3-5 hours** |

The builder at `ssh-ng://dylan@builder-hil1-319ea92d` needs
sufficient disk and RAM. Mark envoy with `requiredSystemFeatures =
["big-parallel"]` in production.

---

## 9. Implementation Order

Build packages bottom-up, testing each layer before proceeding:

### Phase 1: Foundation (supports Bazel)
1. `pkgs/compression/zip.nix`
2. `pkgs/compression/unzip.nix`
3. `pkgs/core/which.nix`
4. `pkgs/toolchain/openjdk21-bootstrap.nix` (binary download)
5. `pkgs/toolchain/openjdk21.nix` (build from source)

**Test**: `java -version`, `javac HelloWorld.java`, `java HelloWorld`

### Phase 2: Bazel
6. `pkgs/build-systems/bazel-bootstrap.nix` (binary download)
7. `pkgs/build-systems/bazel-deps.nix` (FOD, vendored deps)
8. `pkgs/build-systems/bazel.nix` (from source)

**Test**: `bazel version`, build a simple C++ hello world

### Phase 3: Envoy Dependencies
9. `pkgs/toolchain/openjdk11.nix` (if needed by Envoy)
10. `pkgs/build-systems/gn.nix`

### Phase 4: Envoy
11. `pkgs/networking/envoy-deps.nix` (FOD)
12. `pkgs/networking/envoy.nix` (from source)

**Test**: `envoy --version`, basic listener/cluster config

### Phase 5: Integration
13. Update `systems/golden.nix` to include envoy
14. Add Envoy to Cilium's Envoy integration test
15. VM boot test with Envoy proxy configuration

---

## Notes

- **Builder shell**: Remember the builder runs `/bin/sh` (dash).
  Use `$CONFIG_SHELL` for bash-specific syntax. All phase scripts
  shown above should be tested against dash compatibility.
- **Nix string escaping**: In `'' ... ''` strings, use `''${var}` for
  literal shell `${var}` expansion. Watch for this in Bazel wrapper scripts.
- **Hash computation**: Use `nix-prefetch-url` for flat hashes (tarballs)
  and `nix hash path` for recursive hashes (FOD directories). Or use
  `aos prefetch` for AOS-convention hashes.
- **Binary bootstraps are build deps only**: openjdk21-bootstrap and
  bazel-bootstrap never appear in the golden image. They exist only
  to build the from-source versions.
