##! Bazel 7 — build tool compiled from source
##!
##! Three-stage bootstrap: (1) binary bazel-bootstrap vendors external deps
##! into a fixed-output derivation, (2) compile.sh builds a minimal Bazel
##! from javac, (3) that minimal Bazel builds the real Bazel using vendored
##! deps with --repository_disable_download.
{
  mkDerivation,
  fetchurl,
  lib,
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
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  bazel-bootstrap,
}: let
  version = "7.7.1";

  # All tools Bazel needs in PATH during build and at runtime
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
    grep
    gzip
    patch
    diffutils
    findutils
    sed
    tar
    xz
    file
  ];

  src = fetchurl {
    urls = [
      "https://github.com/bazelbuild/bazel/releases/download/${version}/bazel-${version}-dist.zip"
    ];
    hash = "sha256-YYGzVwwvZX2YmxFB+wwaCOtfCBBspXfcfcUufQI4N5o=";
  };

  # Fixed-output derivation: vendor all external dependencies using
  # bazel-bootstrap in --batch mode. The vendor_dir contains all BCR
  # modules and their transitive deps. Repos with local=True (like
  # bazel_features globals_repo) are NOT included — they regenerate
  # dynamically at build time under the real Bazel version.
  vendorDeps = builtins.derivation {
    name = "bazel-vendor-deps-${version}";
    system = lib.system;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${toolsPath}:${openjdk}/bin:${bazel-bootstrap}/bin:$PATH"
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"
        export JAVA_HOME="${openjdk}"

        # Extract dist zip
        mkdir -p "$TMPDIR/bazel_src"
        cd "$TMPDIR/bazel_src"
        unzip -q ${src}

        # Apply reproducibility patch
        patch -p1 < ${./bazel-patches/test_source_sort.patch} || true

        # Fetch module metadata first (may help vendor resolve correctly)
        bazel --batch \
          --output_user_root="$TMPDIR/bazel_cache" \
          --server_javabase="${openjdk}" \
          mod deps --curses=no || true

        # Vendor all external dependencies
        bazel --batch \
          --output_user_root="$TMPDIR/bazel_cache" \
          --server_javabase="${openjdk}" \
          vendor //src:bazel_nojdk \
          --curses=no \
          --vendor_dir="$out" \
          --verbose_failures

        # Clean non-reproducible artifacts
        find "$out" -name "*.pyc" -type f -delete
        rm -rf "$out/gazelle~~non_module_deps~bazel_gazelle_go_repository_cache/gocache" 2>/dev/null || true
        rm -f "$out/rules_go~~go_sdk~go_default_sdk/versions.json" 2>/dev/null || true
        rm -f "$out/bazel-external" 2>/dev/null || true
      ''
    ];

    outputHash = "sha256-+wfJ4WVI/rAAyrz9dVNIajr4dSK/zTnRJTKmAIY6/Fo=";
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };
in
  mkDerivation {
    pname = "bazel";
    inherit version;

    inherit src;

    buildDeps = [
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
      grep
      gzip
      patch
      diffutils
      findutils
      sed
      tar
      xz
      file
    ];
    runtimeDeps = [
      bash
      coreutils
      which
      zip
      unzip
      gawk
      python3
      openjdk
      findutils
      file
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          # Bazel source is a zip, not a tarball
          mkdir bazel_src
          cd bazel_src
          unzip -q $src
        '';
      }
      {
        name = "patch";
        script = ''
          # Apply patches
          patch -p1 < ${./bazel-patches/java_toolchain.patch} || true
          patch -p1 < ${./bazel-patches/test_source_sort.patch} || true

          # Replace hardcoded paths throughout the source tree
          find . -type f \( -name '*.sh' -o -name '*.bzl' -o -name 'BUILD' \
               -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name '*.py' \
               -o -name '*.java' -o -name '*.cc' -o -name '*.tpl' \
               -o -name '*.txt' \) | \
            while read f; do
              sed -i \
                -e "s|/usr/local/bin/bash|${bash}/bin/bash|g" \
                -e "s|/usr/bin/bash|${bash}/bin/bash|g" \
                -e "s|/bin/bash|${bash}/bin/bash|g" \
                -e "s|/usr/bin/env python|${python3}/bin/python3|g" \
                -e "s|/usr/bin/env bash|${bash}/bin/bash|g" \
                -e "s|/usr/bin/env|${coreutils}/bin/env|g" \
                -e "s|/bin/true|${coreutils}/bin/true|g" \
                "$f" 2>/dev/null || true
            done

          # Patch Python bootstrap template shebang placeholder
          sed -i "s|%shebang%|#!${python3}/bin/python3|" \
            tools/python/python_bootstrap_template.txt 2>/dev/null || true

          # Apply strict_action_env patch (substitute placeholder with AOS tool paths)
          patch -p1 < ${./bazel-patches/strict_action_env.patch} || true
          sed -i "s|@strictActionEnvPatch@|${toolsPath}|g" \
            src/main/java/com/google/devtools/build/lib/bazel/rules/BazelRuleClassProvider.java

          # Apply bazel_rc patch and substitute placeholder
          patch -p1 < ${./bazel-patches/bazel_rc.patch} || true
          sed -i "s|@bazelSystemBazelRCPath@|/dev/null|g" \
            src/main/cpp/option_processor.cc
        '';
      }
      {
        name = "build";
        script = ''
          # Set up vendor directory from FOD output
          cp -a ${vendorDeps} ../vendor_dir
          chmod -R u+w ../vendor_dir

          # Regenerate VENDOR.bazel — only pin directories that exist in the
          # vendor dir. Repos with local=True (e.g. bazel_features globals_repo)
          # are NOT in the vendor dir, so they won't be pinned and will
          # regenerate dynamically under the bootstrap Bazel (7.7.1).
          rm -f ../vendor_dir/VENDOR.bazel
          find ../vendor_dir -maxdepth 1 -mindepth 1 -type d -printf 'pin("@@%P")\n' > ../vendor_dir/VENDOR.bazel

          # Fix for bootstrap Bazel: the javac-compiled bootstrap Bazel reports
          # an empty native.bazel_version. bazel_features' parse_version treats
          # empty strings as "dev" (999999.999999.999999), causing globals_repo
          # to generate `macro = macro` (Bazel 8+ builtin) instead of
          # `macro = None`. Patch to treat empty version as 0.0.0.
          sed -i 's|v = "999999.999999.999999"|v = "0.0.0"|' \
            ../vendor_dir/bazel_features~/private/parse.bzl

          # Patch shebangs in vendored Python stubs and templates
          find ../vendor_dir -type f \( -name '*.py' -o -name '*.txt' -o -name '*.tpl' \) | \
            while read f; do
              sed -i \
                -e "s|/usr/bin/env python3|${python3}/bin/python3|g" \
                -e "s|/usr/bin/env python|${python3}/bin/python3|g" \
                -e "s|/usr/bin/env bash|${bash}/bin/bash|g" \
                -e "s|/usr/bin/env|${coreutils}/bin/env|g" \
                -e "s|/bin/bash|${bash}/bin/bash|g" \
                "$f" 2>/dev/null || true
            done

          # Derive bootstrapTools lib path from CONFIG_SHELL (set by mkDerivation)
          BT_LIB=$(dirname "$(dirname "$CONFIG_SHELL")")/lib

          # Create a bash wrapper that always sets PATH and LD_LIBRARY_PATH.
          # Bazel genrules use `exec env -` which strips all vars including PATH.
          # The --action_env flags don't work with the javac-compiled bootstrap
          # Bazel for genrules. We use --shell_executable to point to this wrapper.
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
          export EMBED_LABEL="${version}- (@non-git)"
          export PATH="${toolsPath}:$PATH"

          # Unset C_INCLUDE_PATH so Bazel's CC toolchain auto-detection doesn't
          # pick up bootstrapTools/include as a -I flag, which breaks
          # #include_next <stdlib.h> in the C++ standard library headers.
          # The cc-wrapper's built-in -isystem flag provides glibc headers.
          unset C_INCLUDE_PATH CPATH CPLUS_INCLUDE_PATH

          # Fix shebangs in compile.sh and bootstrap scripts
          sed -i "s|#!/bin/bash|#!${bash}/bin/bash|g" compile.sh
          sed -i "s|#!/bin/bash|#!${bash}/bin/bash|g" scripts/bootstrap/compile.sh
          sed -i "s|shasum -a 256|sha256sum|g" scripts/bootstrap/compile.sh

          # Patch compile.sh: remove --action_env=PATH (inherit from host, which
          # is empty under env -). Our EXTRA_BAZEL_ARGS provides an explicit
          # --action_env=PATH=${toolsPath} instead. Also fix --build_python_zip.
          sed -i '/--action_env=PATH/d' compile.sh
          sed -i "s|--build_python_zip|--nobuild_python_zip|g" scripts/bootstrap/compile.sh

          # Set EXTRA_BAZEL_ARGS which gets included in _BAZEL_ARGS in bootstrap.sh.
          # --vendor_dir provides all vendored deps from the FOD.
          # --repository_disable_download prevents any network access.
          VENDOR_ABS="$(cd ../vendor_dir && pwd)"
          export EXTRA_BAZEL_ARGS="
            --verbose_failures
            --curses=no
            --tool_java_runtime_version=local_jdk_21
            --java_runtime_version=local_jdk_21
            --tool_java_language_version=21
            --java_language_version=21
            --extra_toolchains=@bazel_tools//tools/jdk:all
            --vendor_dir=$VENDOR_ABS
            --repository_disable_download
            --nobuild_python_zip
            --incompatible_strict_action_env
            --action_env=PATH=${toolsPath}
            --host_action_env=PATH=${toolsPath}
            --action_env=LD_LIBRARY_PATH=$BT_LIB
            --host_action_env=LD_LIBRARY_PATH=$BT_LIB
            --shell_executable=$(cd ../tools && pwd)/bash-with-path
          "

          # Run the bootstrap build
          ${bash}/bin/bash ./compile.sh
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share

          # Create bazelrc with AOS defaults
          cat > $out/share/bazel.bazelrc << BAZELRC
          startup --server_javabase=${openjdk}
          build --extra_toolchains=@bazel_tools//tools/jdk:all
          build --tool_java_runtime_version=local_jdk
          build --java_runtime_version=local_jdk
          try-import /etc/bazel.bazelrc
          BAZELRC

          BAZEL_BIN=output/bazel
          if [ ! -f "$BAZEL_BIN" ]; then
            echo "ERROR: compile.sh did not produce output/bazel" >&2
            exit 1
          fi

          # Install the binary
          cp "$BAZEL_BIN" $out/bin/bazel-real
          chmod +x $out/bin/bazel-real

          # Patch ELF
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
                   $out/bin/bazel-real 2>/dev/null || true

          # Create wrapper script
          cat > $out/bin/bazel << WRAPPER
          #!${bash}/bin/bash
          export PATH="${toolsPath}:\$PATH"
          export JAVA_HOME="${openjdk}"
          exec $out/bin/bazel-real "\$@"
          WRAPPER
          chmod +x $out/bin/bazel

          # Save references for Nix's scanner
          mkdir -p $out/nix-support
          echo "${toolsPath}" >> $out/nix-support/depends
        '';
      }
    ];

    meta = {
      description = "Bazel 7 — build and test tool built from source";
      homepage = "https://bazel.build";
      license = "Apache-2.0";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkVMTest {
        name = "build-systems-bazel-version";
        rootfsDeps = [self];
        testScript = ''
          OUTPUT=$(bazel --version 2>&1)
          case "$OUTPUT" in
            *"7.7"*)
              echo "==> bazel version: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected bazel version: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };
    };
  }
