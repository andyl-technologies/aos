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
  supportsChangeId ? true,
  # Bootstrap accepted target split-debuginfo starting in Rust 1.78.
  supportsSplitDebuginfo ? builtins.compareVersions version "1.78.0" >= 0,
  # Older bootstrap tools use the ambient zlib/OpenSSL search path while
  # constructing native stage tools, before switching to the target linker.
  needsNativeCryptoBuildDeps ? builtins.compareVersions version "1.93.0" < 0,
  # Cargo 1.79 through 1.92 can omit libz-sys's native -lz edge while linking
  # its Linux build script even though flate2 selected the system-zlib backend.
  needsNativeZlibLink ? builtins.compareVersions version "1.79.0" >= 0 && builtins.compareVersions version "1.93.0" < 0,
  description,
  buildTool ? null,
}: let
  buildTriple = stdenv.buildPlatform.config;
  buildTripleEnv = builtins.replaceStrings ["-"] ["_"] buildTriple;
  hostTriple = stdenv.hostPlatform.config;
  targetList = builtins.toJSON ([hostTriple] ++ additionalTargets);
  toolList = builtins.toJSON tools;
  isFinal = builtins.elem "dev" outputs;
in
  mkDerivation {
    inherit pname version src outputs;

    buildDeps =
      [
        gnumake
        cmake
        ninja
        pkg-config
        python3
        buildPackages.bash
        buildPackages.which
      ]
      ++ (
        if needsNativeCryptoBuildDeps
        then [buildPackages.openssl buildPackages.zlib]
        else []
      )
      ++ [nativeRust nativeLlvm];
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
          cd rustc-${version}-src${
            if builtins.compareVersions version "1.76.0" < 0
            then "\n          patch -p1 < ${./rust-compiler-rt-darwin-cfi-order.patch}"
            else ""
          }
          ${
            if
              builtins.compareVersions version "1.75.0"
              >= 0
              && builtins.compareVersions version "1.77.0" < 0
            then "patch --fuzz=0 -p1 < ${./rust-bootstrap-vendored-remap.patch}"
            else ""
          }
          ${
            if
              builtins.compareVersions version "1.74.0"
              >= 0
              && builtins.compareVersions version "1.93.0" < 0
            then ''
                  secure_transport_sources=$(find vendor -path '*/curl/lib/vtls/sectransp.c' -print)
                  [ -n "$secure_transport_sources" ]
                  while IFS= read -r secure_transport_source; do
                    secure_transport_root=$(dirname "$(dirname "$(dirname "$(dirname "$secure_transport_source")")")")
                    patch --fuzz=0 -d "$secure_transport_root" -p1 < ${./rust-curl-securetransport-fcntl.patch}
                    checksum_file="$secure_transport_root/.cargo-checksum.json"
                    [ "$(grep -o '"curl/lib/vtls/sectransp.c":"[0-9a-f]\{64\}"' "$checksum_file" | wc -l)" -eq 1 ]
                    secure_transport_checksum=$(sha256sum "$secure_transport_source" | cut -d ' ' -f 1)
                    sed -i "s/\"curl\/lib\/vtls\/sectransp.c\":\"[0-9a-f]\\{64\\}\"/\"curl\/lib\/vtls\/sectransp.c\":\"$secure_transport_checksum\"/" "$checksum_file"
                    [ "$(grep -o '"curl/lib/vtls/sectransp.c":"[0-9a-f]\{64\}"' "$checksum_file" | cut -d '"' -f 4)" = "$secure_transport_checksum" ]
                  done <<EOF
              $secure_transport_sources
              EOF
            ''
            else ""
          }
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
          unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH${
            if needsNativeCryptoBuildDeps
            then "\nexport LIBRARY_PATH=\"${buildPackages.openssl}/lib:${buildPackages.zlib}/lib\""
            else " LIBRARY_PATH"
          }
          unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE SDKROOT
          # The stage-1 Linux rustc links the native shared LLVM, and x.py
          # replaces LD_LIBRARY_PATH with its stage sysroot when executing it.
          # Preserve only that native runtime search path in the executable;
          # the inherited NIX_LDFLAGS points at Darwin libraries and ld64.
          export NIX_LDFLAGS="-Wl,-rpath,${nativeLlvm}/lib"
          ${
            if needsNativeCryptoBuildDeps
            then ''
              translated_args=()
              for arg in "\$@"; do
                case "\$arg" in
                  "${openssl}"/*)
                    arg="${buildPackages.openssl}/\''${arg#"${openssl}/"}"
                    ;;
                  "${zlib}"/*)
                    arg="${buildPackages.zlib}/\''${arg#"${zlib}/"}"
                    ;;
                esac
                translated_args+=("\$arg")
              done
              ${
                if needsNativeZlibLink
                then ''
                  linking=1
                  for arg in "\$@"; do
                    case "\$arg" in
                      -c|-E|-S) linking=0 ;;
                    esac
                  done
                  if [ "\$linking" -eq 1 ]; then
                    translated_args+=("-lz")
                  fi
                ''
                else ""
              }
              exec "$native_compiler" "\''${translated_args[@]}"
            ''
            else ''
              exec "$native_compiler" "\$@"
            ''
          }
          EOF
            chmod +x "$wrapper"
          }
          mkdir -p .aos-build-tools
          write_build_compiler "${buildPackages.cc}/bin/cc" .aos-build-tools/cc-for-build
          write_build_compiler "${buildPackages.cc}/bin/c++" .aos-build-tools/cxx-for-build

          # Every supported bootstrap generation accepts a target linker,
          # while target-local rustflags were added only after Rust 1.79.
          # Keep the direct C++ runtime dependencies required by the external
          # LLVM dylib in a version-stable linker wrapper.
          cat > .aos-build-tools/linker-for-host <<EOF
          #!${buildPackages.bash}/bin/bash
          translated_args=()
          for arg in "\$@"; do
            case "\$arg" in
              "${nativeLlvm}"/*)
                # Rust 1.77 and later reuse the build compiler's external-LLVM
                # link metadata while emitting the Darwin-hosted compiler.
                # Redirect that equivalent native store prefix to the target
                # LLVM; passing the ELF libLLVM to ld64 is never valid.
                arg="${
            if targetLlvm != null
            then targetLlvm
            else nativeLlvm
          }/\''${arg#"${nativeLlvm}/"}"
                ;;
              -lLLVM-*)
                # The native package exposes libLLVM-MAJOR.so while Darwin's
                # canonical shared output is libLLVM.dylib.  Rust 1.77 emits
                # the native soname after correctly selecting the target
                # llvm-config, so bind the equivalent target dylib directly.
                arg="${
            if targetLlvm != null
            then targetLlvm
            else nativeLlvm
          }/lib/libLLVM.dylib"
                ;;
            esac
            translated_args+=("\$arg")
          done
          exec "$CC" "\''${translated_args[@]}" ${
            if targetLlvm != null
            then "-L${targetLlvm}/lib -L${targetLlvm}/lib/darwin"
            else ""
          } -lc++abi -lunwind
          EOF
          chmod +x .aos-build-tools/linker-for-host

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
          ${
            if supportsChangeId
            then "change-id = ${toString changeId}"
            else ""
          }

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
          # Stable bootstrap defaults optimized compiler builtins on. Keep
          # that version-stable policy instead of the newer target-local key,
          # which Rust 1.74 through 1.77 do not recognize.
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
          linker = "$PWD/.aos-build-tools/linker-for-host"
          ar = "$AR"
          ranlib = "$RANLIB"
          ${
            if supportsSplitDebuginfo
            then ''split-debuginfo = "unpacked"''
            else ""
          }
          ${
            if targetLlvm != null
            then ''
              llvm-config = "$PWD/.aos-build-tools/llvm-config-for-host"
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
          TOML${
            if disableLld
            then ''

              [ "$(grep -Ec '^[[:space:]]*lld = false$' ${configFileName})" -eq 1 ]
              [ "$(grep -Ec '^[[:space:]]*use-lld = false$' ${configFileName})" -eq 1 ]
            ''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export RUST_BACKTRACE=1${
            if needsNativeCryptoBuildDeps
            then
              "\n          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=\"$PWD/.aos-build-tools/cc-for-build\""
              + (
                if needsNativeZlibLink
                then ''

                  # cc-rs build dependencies can be compiled while Cargo itself is a
                  # Darwin target tool.  Pin the build triple explicitly so they never
                  # fall back to the ambient target compiler (and its Darwin SDK/PAC
                  # policy) for Linux helper objects.
                  export CC_${buildTripleEnv}="$PWD/.aos-build-tools/cc-for-build"
                  export CXX_${buildTripleEnv}="$PWD/.aos-build-tools/cxx-for-build"
                  export AR_${buildTripleEnv}="${nativeLlvm}/bin/llvm-ar"''
                else ""
              )
            else ""
          }
          export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"

          # Cargo itself is a Darwin artifact, while the build scripts that
          # produce it execute on Linux.  The build-compiler wrapper maps only
          # explicit target OpenSSL/zlib paths back to their native equivalents.
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
          export PATH="$PWD/.fake-bin:$PATH"${
            if needsNativeCryptoBuildDeps
            then
              "\n          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=\"$PWD/.aos-build-tools/cc-for-build\""
              + (
                if needsNativeZlibLink
                then ''

                  export CC_${buildTripleEnv}="$PWD/.aos-build-tools/cc-for-build"
                  export CXX_${buildTripleEnv}="$PWD/.aos-build-tools/cxx-for-build"
                  export AR_${buildTripleEnv}="${nativeLlvm}/bin/llvm-ar"''
                else ""
              )
            else ""
          }
          export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0

          # Stage 2 is still built entirely by the Linux stage-1 compiler; no
          # Mach-O executable is run during installation.
          python3 x.py install --stage 2${
            if
              builtins.compareVersions version "1.75.0"
              >= 0
              && builtins.compareVersions version "1.78.0" < 0
            then ''

              # Rust 1.75 through 1.77 bootstrap Cargo builds shipped
              # proc-macro dylibs before compiler-managed remap flags take
              # effect. Rewrite only the
              # equal-length source-root prefix so Mach-O offsets remain stable.
              old_source_root="/build/rustc-${version}-src"
              remapped_source_root="/rustc/${version}/src______"
              [ "''${#old_source_root}" -eq "''${#remapped_source_root}" ]
              if ! grep -R -a -l -m1 -F "$old_source_root" "$out" >/dev/null; then
                echo "Rust output did not contain its expected bootstrap source root" >&2
                exit 1
              fi
              find "$out" -type f -exec sed -i \
                "s|$old_source_root|$remapped_source_root|g" {} +
              if grep -R -a -l -m1 -F "$old_source_root" "$out" >/dev/null; then
                echo "Rust output retains its bootstrap source root" >&2
                exit 1
              fi
            ''
            else ""
          }

          # x.py preserves its copy transcript as install.log. The compiler
          # artifacts use bootstrap's debuginfo remapping, but this text
          # metadata records the sandbox source root verbatim. Preserve the
          # transcript while giving it the same canonical Rust source prefix.
          install_log="$out/lib/rustlib/install.log"
          if [ ! -f "$install_log" ]; then
            echo "Rust installation did not produce install.log" >&2
            exit 1
          fi
          sed -i \
            -e "s|/build/rustc-${version}-src/build/|/rustc/${version}/bootstrap/|g" \
            -e "s|/build/rustc-${version}-src|/rustc/${version}|g" \
            "$install_log"
          # Canonical remapped source paths can contain ordinary `build/`
          # components. Reject only the original absolute sandbox source root.
          if grep -F "/build/rustc-${version}-src" "$install_log" >/dev/null; then
            echo "Rust install.log retains its sandbox source root" >&2
            exit 1
          fi

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
