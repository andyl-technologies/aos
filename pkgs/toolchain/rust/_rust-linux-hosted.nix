##! Builds a target-hosted Linux Rust toolchain on a Linux scheduler.
##!
##! Rust bootstrap distinguishes the compiler that executes build scripts from
##! the compiler being produced. The stage-0 Rust and LLVM packages execute on
##! the build platform; stage 1 uses the cross C toolchain to produce stage-2
##! rustc, Cargo, rustdoc, tools, and standard libraries for the selected Linux
##! host without executing those target-hosted artifacts during the build.
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
  curl,
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
  supportsSplitDebuginfo ? builtins.compareVersions version "1.78.0" >= 0,
  needsNativeCryptoBuildDeps ? builtins.compareVersions version "1.93.0" < 0,
  needsNativeZlibLink ? builtins.compareVersions version "1.79.0" >= 0 && builtins.compareVersions version "1.93.0" < 0,
  description,
  buildTool ? null,
}: let
  buildTriple = stdenv.buildPlatform.config;
  buildTripleEnv = builtins.replaceStrings ["-"] ["_"] buildTriple;
  cargoBuildTripleEnv =
    if buildTriple == "x86_64-unknown-linux-gnu"
    then "X86_64_UNKNOWN_LINUX_GNU"
    else if buildTriple == "aarch64-unknown-linux-gnu"
    then "AARCH64_UNKNOWN_LINUX_GNU"
    else throw "${pname}: unsupported build triple '${buildTriple}'";
  hostTriple = stdenv.hostPlatform.config;
  hostTripleEnv = builtins.replaceStrings ["-"] ["_"] hostTriple;
  targetList = builtins.toJSON ([hostTriple] ++ additionalTargets);
  toolList = builtins.toJSON tools;
  isFinal = builtins.elem "dev" outputs;
  crossCc = stdenv.cc;
  targetLlvmPackage =
    if targetLlvm != null
    then targetLlvm
    else throw "${pname}: target-hosted Linux Rust requires a target LLVM";
  objdumpArchitecture =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else if stdenv.hostPlatform.isx86_64
    then "i386:x86-64"
    else throw "${pname}: unsupported target '${stdenv.hostPlatform.system}'";
  nativeLlvmVersion = nativeLlvm.version or (throw "${pname}: native LLVM has no version attribute");
  targetLlvmVersion = targetLlvmPackage.version or (throw "${pname}: target LLVM has no version attribute");
  # pkg-config validates curl's transitive Requires entries even for dynamic
  # linkage. Keep each complete dependency graph on its own platform.
  pkgConfigPath = roots: let
    entry = package: {
      key = package.outPath;
      inherit package;
    };
    closure = builtins.genericClosure {
      startSet = map entry roots;
      operator = node:
        map entry (
          (node.package.propagatedDeps or [])
          ++ (node.package.runtimeDeps or [])
        );
    };
  in
    builtins.concatStringsSep ":" (map (node: "${node.package}/lib/pkgconfig") closure);
  nativePkgConfigPath = pkgConfigPath [buildPackages.curl buildPackages.openssl buildPackages.zlib buildPackages.xz];
  targetPkgConfigPath = pkgConfigPath [curl openssl zlib];
  additionalTargetChecks = builtins.concatStringsSep "\n" (map (target: ''
      target_library="$out/lib/rustlib/${target}/lib"
      for library in std core alloc compiler_builtins panic_abort; do
        if ! find "$target_library" -name "lib$library-*.rlib" -type f -print -quit | grep -q .; then
          echo "Rust $library library for ${target} was not installed" >&2
          exit 1
        fi
      done
    '')
    additionalTargets);
in
  if !stdenv.isCross || !stdenv.hostPlatform.isLinux
  then throw "${pname}: target-hosted Linux Rust requires a cross Linux stdenv"
  else if nativeLlvmVersion != targetLlvmVersion
  then throw "${pname}: native LLVM ${nativeLlvmVersion} does not match target LLVM ${targetLlvmVersion}"
  else
    mkDerivation {
      inherit pname version src outputs;

      buildDeps =
        [
          buildPackages.gnumake
          buildPackages.cmake
          buildPackages.ninja
          buildPackages.pkg-config
          buildPackages.python3
          buildPackages.bash
          buildPackages.which
          buildPackages.curl
          buildPackages.xz
          nativeRust
          nativeLlvm
          crossCc
        ]
        ++ (
          if needsNativeCryptoBuildDeps
          then [
            buildPackages.openssl
            buildPackages.zlib
          ]
          else []
        );
      runtimeDeps = [
        curl
        openssl
        zlib
        targetLlvmPackage
      ];
      propagatedDeps = [];

      # No scheduler compiler, bootstrap compiler, or native LLVM may survive in
      # a toolchain whose public executables must run on the selected Linux host.
      disallowedReferences = [
        nativeRust
        nativeLlvm
        crossCc
        buildPackages.cc
        buildPackages.curl
        buildPackages.xz
        buildPackages.openssl
        buildPackages.zlib
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd rustc-${version}-src

            ${
              if builtins.compareVersions version "1.98.0" < 0
              then ''
                # Older bootstrap Cargo releases vendor openssl-sys versions
                # that reject OpenSSL 4 before compiling even though they use
                # only the OpenSSL 3-compatible API subset. Remove that obsolete
                # check and update Cargo's vendored-source checksum.
                patched_openssl_sys=0
                for openssl_sys_build in vendor/openssl-sys*/build/main.rs; do
                  test -f "$openssl_sys_build" || continue${
                  if version == "1.97.0"
                  then ''

                    # openssl-sys 0.9.114 supports OpenSSL 4 and rejects only the
                    # unreleased next major. Leave that branch intact.
                    grep -q 'Version::Openssl4xx' "$openssl_sys_build" && continue
                  ''
                  else ""
                }
                  grep -q 'if openssl_version >= 0x4_00_00_00_0 {' "$openssl_sys_build" || continue

                  test "$(grep -c 'if openssl_version >= 0x4_00_00_00_0 {' "$openssl_sys_build")" -eq 1
                  sed -i \
                    '/if openssl_version >= 0x4_00_00_00_0 {/,/} else if openssl_version >= 0x3_00_00_00_0 {/c\        if openssl_version >= 0x3_00_00_00_0 {' \
                    "$openssl_sys_build"
                  test "$(grep -c 'if openssl_version >= 0x4_00_00_00_0 {' "$openssl_sys_build")" -eq 0

                  openssl_sys_dir=''${openssl_sys_build%/build/main.rs}
                  openssl_sys_checksum=$openssl_sys_dir/.cargo-checksum.json
                  test "$(grep -o '\"build/main.rs\":\"[0-9a-f]*\"' "$openssl_sys_checksum" | wc -l)" -eq 1
                  updated_checksum=$(sha256sum "$openssl_sys_build")
                  updated_checksum=''${updated_checksum%% *}
                  sed -i \
                    "s|\"build/main.rs\":\"[0-9a-f]*\"|\"build/main.rs\":\"$updated_checksum\"|" \
                    "$openssl_sys_checksum"
                  grep -q "\"build/main.rs\":\"$updated_checksum\"" "$openssl_sys_checksum"

                  patched_openssl_sys=$((patched_openssl_sys + 1))
                done
                test "$patched_openssl_sys" -ge 1
              ''
              else ""
            }
          '';
        }
        {
          name = "configure";
          script =
            ''
              ${
                # Rust 1.76 retains the 1.75 bootstrap and proc-macro behavior.
                if builtins.elem version ["1.75.0" "1.76.0"]
                then ''
                  # Offline vendoring leaves the registry mapping empty. Ignore
                  # that empty entry instead of passing an invalid rustc flag.
                  bootstrap_rustc=src/bootstrap/src/bin/rustc.rs
                  test "$(grep -Fc 'for map in maps.split(' "$bootstrap_rustc")" -eq 1
                  sed -i \
                    '/for map in maps.split(/s/) {/).filter(|map| !map.is_empty()) {/' \
                    "$bootstrap_rustc"

                  # Rust 1.75 bypasses explicit path remapping for proc-macro
                  # crates. Distributed target macros need the same reproducible
                  # source names as the compiler and its other libraries.
                  compiler_session=compiler/rustc_session/src/session.rs
                  test "$(grep -Fc 'CrateType::ProcMacro => return false,' "$compiler_session")" -eq 1
                  sed -i \
                    's/CrateType::ProcMacro => return false,/CrateType::ProcMacro => continue,/' \
                    "$compiler_session"
                ''
                else ""
              }

              ${
                if builtins.elem version ["1.74.0" "1.75.0" "1.76.0"]
                then ''
                  # Bootstrap embeds the configured llvm-config path as the
                  # custom-LLVM marker. Name the installed target tool there;
                  # LLVM_CONFIG still runs the scheduler wrapper during builds.
                  bootstrap_compile=src/bootstrap/compile.rs
                  if [ ! -f "$bootstrap_compile" ]; then
                    bootstrap_compile=src/bootstrap/src/core/build_steps/compile.rs
                  fi
                  test "$(grep -Fc 'cargo.env("CFG_LLVM_ROOT", s);' "$bootstrap_compile")" -eq 1
                  test "$(grep -Fc 'if let Some(s) = target_config.and_then(|c| c.llvm_config.as_ref()) {' "$bootstrap_compile")" -eq 1
                  sed -i \
                    -e 's/if let Some(s) = target_config.and_then(|c| c.llvm_config.as_ref()) {/if target_config.and_then(|c| c.llvm_config.as_ref()).is_some() {/' \
                    -e 's|cargo.env("CFG_LLVM_ROOT", s);|cargo.env("CFG_LLVM_ROOT", "${targetLlvmPackage}/bin/llvm-config");|' \
                    "$bootstrap_compile"
                ''
                else ""
              }

              case "$NIX_BUILD_CORES" in
                ""|*[!0-9]*|0)
                  echo "NIX_BUILD_CORES must be a positive integer" >&2
                  exit 1
                  ;;
              esac

              # Release tarballs carry authoritative version metadata. Prevent
              # bootstrap from consulting a worktree or network through Git.
              mkdir -p .fake-bin
              printf '%s\n' '#!${buildPackages.bash}/bin/bash' 'exit 1' > .fake-bin/git
              chmod +x .fake-bin/git

              # Bootstrap invokes strip by name for both scheduler and target
              # libraries. LLVM's native executable understands both object
              # architectures; the cross GNU strip only understands the target.
              ln -s ${nativeLlvm}/bin/llvm-strip .fake-bin/strip
              export PATH="$PWD/.fake-bin:$PATH"

              # Bootstrap stage tools execute on the scheduler. Remove cross-only
              # include, linker, and hardening settings before invoking the native
              # compiler, while preserving the native LLVM runtime search path.
              write_build_compiler() {
                native_compiler=$1
                wrapper=$2
                cat > "$wrapper" <<EOF
              #!${buildPackages.bash}/bin/bash
              unset AOS_HARDENING_ENABLE AOS_HARDENING_DISABLE
              unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset NIX_CFLAGS_COMPILE
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH${
                if needsNativeCryptoBuildDeps
                then "\nexport LIBRARY_PATH=\"${buildPackages.openssl}/lib:${buildPackages.zlib}/lib\""
                else " LIBRARY_PATH"
              }
              export NIX_LDFLAGS="-Wl,-rpath,${nativeLlvm}/lib -Wl,-rpath,${buildPackages.xz}/lib"
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

              # rustc_llvm queries llvm-config on the scheduler while linking the
              # resulting compiler against target LLVM. Translate the equivalent
              # package prefix and reject any leaked native path after each query.
              cat > .aos-build-tools/llvm-config-for-host <<EOF
              #!${buildPackages.bash}/bin/bash
              set -euo pipefail
              output="\$("${nativeLlvm}/bin/llvm-config" "\$@" | sed 's|${nativeLlvm}|${targetLlvmPackage}|g')"
              if [[ "\$output" == *'${nativeLlvm}'* ]]; then
                echo "llvm-config retained the native LLVM prefix" >&2
                exit 1
              fi
              printf '%s\n' "\$output"
              EOF
              chmod +x .aos-build-tools/llvm-config-for-host

              # Rust 1.77 and later can retain native LLVM paths in linker metadata
              # inherited from the build compiler. The Linux LLVM layouts and
              # sonames match, so prefix translation is sufficient.
              cat > .aos-build-tools/linker-for-host <<EOF
              #!${buildPackages.bash}/bin/bash
              translated_args=()
              for arg in "\$@"; do
                case "\$arg" in
                  "${nativeLlvm}"/*)
                    arg="${targetLlvmPackage}/\''${arg#"${nativeLlvm}/"}"
                    ;;
                esac
                translated_args+=("\$arg")
              done
              exec "${crossCc}/bin/cc" "\''${translated_args[@]}" -L${targetLlvmPackage}/lib
              EOF
              chmod +x .aos-build-tools/linker-for-host

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
              codegen-units = $NIX_BUILD_CORES
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
                then "lld = false\n          ${
                  if builtins.compareVersions version "1.94.0" >= 0
                  then "bootstrap-override-lld"
                  else "use-lld"
                } = false"
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
              cc = "${crossCc}/bin/cc"
              cxx = "${crossCc}/bin/c++"
              linker = "$PWD/.aos-build-tools/linker-for-host"
              ar = "${crossCc}/bin/ar"
              ranlib = "${crossCc}/bin/ranlib"
              llvm-config = "$PWD/.aos-build-tools/llvm-config-for-host"
              ${
                if supportsSplitDebuginfo
                then ''split-debuginfo = "unpacked"''
                else ""
              }

              ${
                if builtins.elem "wasm32-unknown-unknown" additionalTargets
                then ''
                  [target.wasm32-unknown-unknown]
                  optimized-compiler-builtins = false
                  profiler = false
                ''
                else ""
              }
              TOML

              ${
                if disableLld
                then ''
                  [ "$(grep -Ec '^[[:space:]]*lld = false$' ${configFileName})" -eq 1 ]
                  [ "$(grep -Ec '^[[:space:]]*(use-lld|bootstrap-override-lld) = false$' ${configFileName})" -eq 1 ]
                ''
                else ""
              }
            ''
            + (
              if isFinal
              then ''
                # Bootstrap locates distributed LLVM utilities beside the target
                # llvm-config wrapper without executing them on the scheduler.
                # Its installer resolves these links to copy target executables.
                for llvm_tool in \
                  llvm-cov llvm-nm llvm-objcopy llvm-objdump llvm-profdata \
                  llvm-readobj llvm-size llvm-strip llvm-ar llvm-as llvm-dis \
                  llvm-link llc opt
                do
                  test -x "${targetLlvmPackage}/bin/$llvm_tool"
                  ln -s "${targetLlvmPackage}/bin/$llvm_tool" ".aos-build-tools/$llvm_tool"
                done
              ''
              else ""
            );
        }
        {
          name = "build";
          script = ''
            ${
              if builtins.compareVersions version "1.75.0" >= 0
              then ''
                # Vendored Cargo never populates registry/src, but bootstrap's
                # debug-path remapper enumerates it even in offline builds.
                export CARGO_HOME="$PWD/.aos-cargo-home"
                mkdir -p "$CARGO_HOME/registry/src"
              ''
              else ""
            }
            export PATH="$PWD/.fake-bin:$PATH"
            export RUST_BACKTRACE=1
            export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
            export CARGO_TARGET_${cargoBuildTripleEnv}_LINKER="$PWD/.aos-build-tools/cc-for-build"
            export CC_${buildTripleEnv}="$PWD/.aos-build-tools/cc-for-build"
            export CXX_${buildTripleEnv}="$PWD/.aos-build-tools/cxx-for-build"
            export AR_${buildTripleEnv}="${nativeLlvm}/bin/llvm-ar"
            export CC_${hostTripleEnv}="${crossCc}/bin/cc"
            export CXX_${hostTripleEnv}="${crossCc}/bin/c++"
            export AR_${hostTripleEnv}="${crossCc}/bin/ar"

            # Cargo's curl-sys must use the AOS library for the platform it
            # targets. Unqualified search paths mix scheduler and target .pc
            # files and can silently select the wrong OpenSSL dependency.
            export PKG_CONFIG_PATH_${buildTripleEnv}="${nativePkgConfigPath}"
            export PKG_CONFIG_PATH_${hostTripleEnv}="${targetPkgConfigPath}"

            export OPENSSL_DIR=${openssl}
            export OPENSSL_LIB_DIR=${openssl}/lib
            export OPENSSL_INCLUDE_DIR=${openssl}/include
            export OPENSSL_NO_VENDOR=1
            export OPENSSL_STATIC=0

            ${buildPackages.python3}/bin/python3 x.py build --stage 2 -j "$NIX_BUILD_CORES"
          '';
        }
        {
          name = "install";
          script = ''
            ${
              if builtins.compareVersions version "1.75.0" >= 0
              then ''
                export CARGO_HOME="$PWD/.aos-cargo-home"
              ''
              else ""
            }
            export PATH="$PWD/.fake-bin:$PATH"
            export LD_LIBRARY_PATH="${nativeLlvm}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
            export CARGO_TARGET_${cargoBuildTripleEnv}_LINKER="$PWD/.aos-build-tools/cc-for-build"
            export CC_${buildTripleEnv}="$PWD/.aos-build-tools/cc-for-build"
            export CXX_${buildTripleEnv}="$PWD/.aos-build-tools/cxx-for-build"
            export AR_${buildTripleEnv}="${nativeLlvm}/bin/llvm-ar"
            export CC_${hostTripleEnv}="${crossCc}/bin/cc"
            export CXX_${hostTripleEnv}="${crossCc}/bin/c++"
            export AR_${hostTripleEnv}="${crossCc}/bin/ar"
            export PKG_CONFIG_PATH_${buildTripleEnv}="${nativePkgConfigPath}"
            export PKG_CONFIG_PATH_${hostTripleEnv}="${targetPkgConfigPath}"

            export OPENSSL_DIR=${openssl}
            export OPENSSL_LIB_DIR=${openssl}/lib
            export OPENSSL_INCLUDE_DIR=${openssl}/include
            export OPENSSL_NO_VENDOR=1
            export OPENSSL_STATIC=0

            ${buildPackages.python3}/bin/python3 x.py install --stage 2 -j "$NIX_BUILD_CORES"

            install_log="$out/lib/rustlib/install.log"
            if [ ! -f "$install_log" ]; then
              echo "Rust installation did not produce install.log" >&2
              exit 1
            fi
            sed -i \
              -e "s|/build/rustc-${version}-src/build/|/rustc/${version}/bootstrap/|g" \
              -e "s|/build/rustc-${version}-src|/rustc/${version}|g" \
              "$install_log"

            for executable in rustc cargo; do
              if [ ! -x "$out/bin/$executable" ]; then
                echo "Rust installation did not produce $executable" >&2
                exit 1
              fi
              executable_header=$("$OBJDUMP" -f "$out/bin/$executable")
              if ! printf '%s\n' "$executable_header" | grep -Fq 'file format elf'; then
                echo "$executable is not an ELF executable" >&2
                exit 1
              fi
              if ! printf '%s\n' "$executable_header" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
                echo "$executable does not execute on ${stdenv.hostPlatform.system}" >&2
                exit 1
              fi
            done
            if [ -e "$out/bin/rustdoc" ]; then
              if [ ! -x "$out/bin/rustdoc" ]; then
                echo "installed rustdoc is not executable" >&2
                exit 1
              fi
              rustdoc_header=$("$OBJDUMP" -f "$out/bin/rustdoc")
              if ! printf '%s\n' "$rustdoc_header" | grep -Fq 'file format elf'; then
                echo "rustdoc is not an ELF executable" >&2
                exit 1
              fi
              if ! printf '%s\n' "$rustdoc_header" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
                echo "rustdoc does not execute on ${stdenv.hostPlatform.system}" >&2
                exit 1
              fi
            elif ${
              if builtins.elem "rustdoc" tools
              then "true"
              else "false"
            }; then
              echo "Rust installation did not produce requested rustdoc" >&2
              exit 1
            fi

            rustc_driver=$(find "$out/lib" -name 'librustc_driver*.so' -type f -print -quit)
            if [ -z "$rustc_driver" ]; then
              echo "target-hosted rustc driver library was not installed" >&2
              exit 1
            fi
            rustc_driver_header=$("$OBJDUMP" -f "$rustc_driver")
            if ! printf '%s\n' "$rustc_driver_header" | grep -Fq 'file format elf'; then
              echo "rustc driver is not an ELF shared library" >&2
              exit 1
            fi
            if ! printf '%s\n' "$rustc_driver_header" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
              echo "rustc driver does not execute on ${stdenv.hostPlatform.system}" >&2
              exit 1
            fi

            host_library="$out/lib/rustlib/${hostTriple}/lib"
            for library in \
              std core alloc compiler_builtins panic_abort panic_unwind \
              proc_macro test unwind
            do
              if ! find "$host_library" -name "lib$library-*.rlib" -type f -print -quit | grep -q .; then
                echo "Rust $library library for ${hostTriple} was not installed" >&2
                exit 1
              fi
            done
            host_std_shared=$(find "$host_library" -name 'libstd-*.so' -type f -print -quit)
            if [ -z "$host_std_shared" ]; then
              echo "Rust shared standard library for ${hostTriple} was not installed" >&2
              exit 1
            fi
            host_std_header=$("$OBJDUMP" -f "$host_std_shared")
            if ! printf '%s\n' "$host_std_header" | grep -Fq 'file format elf'; then
              echo "Rust shared standard library is not an ELF library" >&2
              exit 1
            fi
            if ! printf '%s\n' "$host_std_header" | grep -Fq 'architecture: ${objdumpArchitecture}'; then
              echo "Rust shared standard library does not target ${stdenv.hostPlatform.system}" >&2
              exit 1
            fi

            ${additionalTargetChecks}

            ${
              if builtins.elem "wasm32-unknown-unknown" additionalTargets
              then ''
                rustlib_bin="$out/lib/rustlib/${hostTriple}/bin"
                mkdir -p "$rustlib_bin"
                ln -s ${targetLlvmPackage}/bin/lld "$rustlib_bin/rust-lld"
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

            # The compiler's remapping and normalized install transcript must
            # remove every reference to the ephemeral Rust source tree from all
            # public outputs, including developer tools and rust-src.
            output_roots="$out${
              if isFinal
              then " $dev"
              else ""
            }"
            if find $output_roots -type f -exec grep -a -l -m1 -F "/build/rustc-${version}-src" {} + | grep -q .; then
              echo "Rust output retains its bootstrap source root" >&2
              exit 1
            fi
          '';
        }
      ];

      passthru =
        {
          inherit buildTriple hostTriple;
          targetHosted = true;
        }
        // (
          if buildTool != null
          then {inherit buildTool;}
          else {}
        );

      meta = {
        inherit description;
        homepage = "https://www.rust-lang.org";
        license = "MIT OR Apache-2.0";
        build = {
          os = "linux";
          cpu = [stdenv.buildPlatform.constraints.cpu];
        };
        execute = {
          os = "linux";
          cpu = [stdenv.hostPlatform.constraints.cpu];
        };
        target = {
          os = "linux";
          cpu = [stdenv.hostPlatform.constraints.cpu];
        };
      };
    }
