##! Builds a Darwin-hosted Rust toolchain on a Linux build platform.
##!
##! Rust bootstrap distinguishes the executable build compiler from the host
##! compiler being produced.  The stage-0 compiler and build-triple LLVM are
##! native AOS packages; bootstrap then cross-builds its in-tree LLVM, rustc,
##! standard library, Cargo, and requested tools for the Darwin host without
##! executing any resulting Mach-O program.
{
  mkDerivation,
  pname,
  version,
  src,
  changeId,
  configFileName,
  nativeRust,
  nativeLlvm,
  buildPackages,
  stdenv,
  gnumake,
  cmake,
  ninja,
  pkg-config,
  python3,
  openssl,
  zlib,
  targetLlvm ? null,
  additionalTargets ? [],
  tools ? ["cargo"],
  outputs ? ["out"],
  profiler ? false,
  needsDownloadRustc ? false,
  disableLld ? false,
  description,
}: let
  buildTriple = stdenv.buildPlatform.config;
  hostTriple = stdenv.hostPlatform.config;
  targetList = builtins.toJSON ([hostTriple] ++ additionalTargets);
  toolList = builtins.toJSON tools;
  isFinal = builtins.elem "dev" outputs;
in
  mkDerivation {
    inherit pname version src outputs;

    buildDeps = [
      gnumake
      cmake
      ninja
      pkg-config
      python3
      buildPackages.bash
      buildPackages.which
      nativeRust
      nativeLlvm
    ];
    runtimeDeps = [zlib openssl] ++ (if targetLlvm != null then [targetLlvm] else []);

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rustc-${version}-src
        '';
      }
      {
        name = "configure";
        script = ''
          # x.py probes Git for developer metadata even for release tarballs.
          # A fail-closed stub prevents network or worktree discovery while
          # allowing the tarball's version metadata to remain authoritative.
          mkdir -p .fake-bin
          printf '%s\n' '#!${buildPackages.bash}/bin/bash' 'exit 1' > .fake-bin/git
          chmod +x .fake-bin/git
          export PATH="$PWD/.fake-bin:$PATH"

          cat > ${configFileName} <<TOML
          change-id = ${toString changeId}

          [llvm]
          link-shared = true
          download-ci-llvm = false
          ninja = true

          [build]
          build = "${buildTriple}"
          host = ["${hostTriple}"]
          target = ${targetList}
          docs = false
          extended = true
          tools = ${toolList}
          vendor = true
          profiler = ${if profiler then "true" else "false"}
          cargo = "${nativeRust}/bin/cargo"
          rustc = "${nativeRust}/bin/rustc"

          [install]
          prefix = "$out"
          sysconfdir = "etc"

          [rust]
          channel = "stable"
          codegen-units = 0
          rpath = true
          omit-git-hash = true
          ${
            if needsDownloadRustc
            then "download-rustc = false"
            else ""
          }
          ${
            if disableLld
            then "lld = false\n          use-lld = false"
            else ""
          }

          [target.${buildTriple}]
          cc = "${buildPackages.cc}/bin/cc"
          cxx = "${buildPackages.cc}/bin/c++"
          linker = "${buildPackages.cc}/bin/cc"
          ar = "${nativeLlvm}/bin/llvm-ar"
          ranlib = "${nativeLlvm}/bin/llvm-ranlib"
          llvm-config = "${nativeLlvm}/bin/llvm-config"

          [target.${hostTriple}]
          cc = "$CC"
          cxx = "$CXX"
          linker = "$CC"
          ar = "$AR"
          ranlib = "$RANLIB"
          llvm-has-rust-patches = true
          optimized-compiler-builtins = true
          split-debuginfo = "unpacked"

          ${
            if builtins.elem "wasm32-unknown-unknown" additionalTargets
            then ''
              [target.wasm32-unknown-unknown]
              optimized-compiler-builtins = false
            ''
            else ""
          }
          TOML
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export RUST_BACKTRACE=1

          # Cargo and its native dependencies are host artifacts.  Their build
          # scripts run on Linux but link the resulting binaries to Darwin
          # OpenSSL and zlib through the cross compiler.
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0

          python3 x.py build -j "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0

          python3 x.py install

          test -x "$out/bin/rustc"
          test -x "$out/bin/cargo"
          "$OBJDUMP" --macho --private-header "$out/bin/rustc" >/dev/null
          "$OBJDUMP" --macho --private-header "$out/bin/cargo" >/dev/null

          rustc_driver=$(find "$out/lib" -name 'librustc_driver*.dylib' -type f -print -quit)
          if [ -z "$rustc_driver" ]; then
            echo "Darwin rustc driver dylib was not installed" >&2
            exit 1
          fi
          "$OBJDUMP" --macho --private-header "$rustc_driver" >/dev/null

          target_std=$(find "$out/lib/rustlib/${hostTriple}/lib" -name 'libstd-*.rlib' -type f -print -quit)
          if [ -z "$target_std" ]; then
            echo "Darwin Rust standard library was not installed" >&2
            exit 1
          fi

          ${
            if builtins.elem "wasm32-unknown-unknown" additionalTargets
            then ''
              wasm_std=$(find "$out/lib/rustlib/wasm32-unknown-unknown/lib" -name 'libstd-*.rlib' -type f -print -quit)
              if [ -z "$wasm_std" ]; then
                echo "wasm32 Rust standard library was not installed" >&2
                exit 1
              fi
            ''
            else ""
          }

          ${
            if targetLlvm != null
            then ''
              # wasm32-unknown-unknown uses rust-lld from the compiler host's
              # sysroot.  The Darwin LLVM package supplies the matching Mach-O
              # universal lld driver, which dispatches on `-flavor wasm`.
              rustlib_bin="$out/lib/rustlib/${hostTriple}/bin"
              mkdir -p "$rustlib_bin"
              ln -sf ${targetLlvm}/bin/lld "$rustlib_bin/rust-lld"
            ''
            else ""
          }

          ${
            if isFinal
            then ''
              mkdir -p "$dev/bin"
              for tool in cargo-clippy clippy-driver cargo-fmt rustfmt rust-analyzer; do
                if [ -e "$out/bin/$tool" ]; then
                  mv "$out/bin/$tool" "$dev/bin/$tool"
                fi
              done

              if [ -d "$out/lib/rustlib/src" ]; then
                mkdir -p "$dev/lib/rustlib"
                mv "$out/lib/rustlib/src" "$dev/lib/rustlib/src"
              fi
            ''
            else ""
          }
        '';
      }
    ];

    meta = {
      inherit description;
      homepage = "https://www.rust-lang.org";
      license = "MIT OR Apache-2.0";
    };
  }
