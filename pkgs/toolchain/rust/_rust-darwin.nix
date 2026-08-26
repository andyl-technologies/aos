##! Builds a Darwin-hosted Rust toolchain on a Linux build platform.
##!
##! Rust bootstrap distinguishes the executable build compiler from the host
##! compiler being produced.  The stage-0 compiler and build-triple LLVM are
##! native AOS packages; bootstrap cross-builds rustc, the standard library,
##! Cargo, and requested tools against the equivalent target LLVM without
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
  buildTool ? null,
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
    runtimeDeps =
      [zlib openssl]
      ++ (
        if targetLlvm != null
        then [targetLlvm]
        else []
      );

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

          # Rust's Python bootstrap uses the build-triple compiler for its own
          # Cargo binary and stage-1 compiler.  Keep Darwin SDK paths and the
          # arm64-only PAC token out of those Linux links while retaining the
          # package's remaining native hardening policy.
          write_build_compiler() {
            native_compiler=$1
            wrapper=$2
            cat > "$wrapper" <<EOF
          #!${buildPackages.bash}/bin/bash
          native_hardening=
          for token in \$AOS_HARDENING_ENABLE; do
            case "\$token" in
              pacret) ;;
              *) native_hardening="\$native_hardening \$token" ;;
            esac
          done
          export AOS_HARDENING_ENABLE="\$native_hardening"
          unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
          unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
          unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE SDKROOT
          # The stage-1 Linux rustc links the native shared LLVM, and x.py
          # replaces LD_LIBRARY_PATH with its stage sysroot when executing it.
          # Preserve only that native runtime search path in the executable;
          # the inherited NIX_LDFLAGS points at Darwin libraries and ld64.
          export NIX_LDFLAGS="-Wl,-rpath,${nativeLlvm}/lib"
          exec "$native_compiler" "\$@"
          EOF
            chmod +x "$wrapper"
          }
          mkdir -p .aos-build-tools
          write_build_compiler "${buildPackages.cc}/bin/cc" .aos-build-tools/cc-for-build
          write_build_compiler "${buildPackages.cc}/bin/c++" .aos-build-tools/cxx-for-build

          ${
            if targetLlvm != null
            then ''
              # llvm-config must execute on the build platform, but its paths
              # must describe the equivalent target LLVM.  Rust's own
              # rustc_llvm build script explicitly supports this Canadian
              # cross arrangement.  Translate only the package prefix; the
              # native and target LLVM packages have identical components and
              # link mode.
              cat > .aos-build-tools/llvm-config-for-host <<EOF
              #!${buildPackages.bash}/bin/bash
              set -euo pipefail
              "${nativeLlvm}/bin/llvm-config" "\$@" | sed 's|${nativeLlvm}|${targetLlvm}|g'
              for arg in "\$@"; do
                if [ "\$arg" = --cxxflags ]; then
                  # The native query reports libstdc++, while the equivalent
                  # Darwin LLVM was built against libc++.  rustc_llvm uses
                  # this flag to select the target C++ runtime at link time.
                  printf '%s\n' '-stdlib=libc++'
                  break
                fi
              done
              EOF
              chmod +x .aos-build-tools/llvm-config-for-host

              # For an external cross LLVM, x.py locates llvm-tools-preview
              # binaries beside the configured llvm-config instead of asking
              # the non-runnable target binary for its bindir.  Make that
              # directory a complete target-tool view while keeping only the
              # llvm-config entry Linux-executable.
              for tool in \
                llvm-cov llvm-nm llvm-objcopy llvm-objdump llvm-profdata \
                llvm-readobj llvm-size llvm-strip llvm-ar llvm-as llvm-dis \
                llvm-link llc opt
              do
                ln -s "${targetLlvm}/bin/$tool" ".aos-build-tools/$tool"
              done
            ''
            else ""
          }

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
          profiler = ${
            if profiler
            then "true"
            else "false"
          }
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
          remap-debuginfo = true
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
          cc = "$PWD/.aos-build-tools/cc-for-build"
          cxx = "$PWD/.aos-build-tools/cxx-for-build"
          linker = "$PWD/.aos-build-tools/cc-for-build"
          ar = "${nativeLlvm}/bin/llvm-ar"
          ranlib = "${nativeLlvm}/bin/llvm-ranlib"
          llvm-config = "${nativeLlvm}/bin/llvm-config"

          [target.${hostTriple}]
          cc = "$CC"
          cxx = "$CXX"
          linker = "$CC"
          ar = "$AR"
          ranlib = "$RANLIB"
          optimized-compiler-builtins = true
          split-debuginfo = "unpacked"
          ${
            if targetLlvm != null
            then ''
              llvm-config = "$PWD/.aos-build-tools/llvm-config-for-host"
              rustflags = [
                "-Lnative=${targetLlvm}/lib",
                "-Lnative=${targetLlvm}/lib/darwin",
                # The target LLVM's libc++ dylib loads libc++abi and libunwind
                # at runtime but does not reexport them.  rustc links with the
                # C driver and -nodefaultlibs, so make those direct C++ runtime
                # dependencies visible while linking rustc_codegen_llvm.
                "-Clink-arg=-lc++abi",
                "-Clink-arg=-lunwind",
              ]
            ''
            else ""
          }

          ${
            if builtins.elem "wasm32-unknown-unknown" additionalTargets
            then ''
              [target.wasm32-unknown-unknown]
              optimized-compiler-builtins = false
              # Bare wasm has no OS profiling runtime.  Leaving the global
              # profiler setting enabled makes bootstrap compile compiler-rt's
              # GCDA implementation, which requires POSIX headers.
              profiler = false
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
          export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"

          # Cargo and its native dependencies are host artifacts.  Their build
          # scripts run on Linux but link the resulting binaries to Darwin
          # OpenSSL and zlib through the cross compiler.
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0

          # A Canadian cross produces the Darwin compiler at stage 2. Stage 1
          # is the Linux compiler that can execute here and build both the
          # Darwin standard library and the stage-2 Darwin compiler.
          python3 x.py build --stage 2 -j "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0

          # Stage 2 is still built entirely by the Linux stage-1 compiler; no
          # Mach-O executable is run during installation.
          python3 x.py install --stage 2

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

    passthru =
      if buildTool != null
      then {inherit buildTool;}
      else {};
  }
