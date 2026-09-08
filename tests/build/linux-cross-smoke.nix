# Build-only smoke coverage for the Linux-hosted AArch64 GNU cross toolchain.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  crucible = cross.pkgs.crucible;
  glibcLocales = cross.pkgs.glibc-locales;
  passt = cross.pkgs.passt;
  postgresql = cross.pkgs.postgresql;
  postgresqlBuildScript = builtins.elemAt postgresql.args 1;
  postgresqlBuildDrivers = builtins.map toString [
    cross.buildPackages.bison
    cross.buildPackages.flex
    cross.buildPackages.gettext
    cross.buildPackages.libxml2
    cross.buildPackages.libxslt
    cross.buildPackages.llvm
    cross.buildPackages.perl
    cross.buildPackages.pkg-config
    cross.buildPackages.python3
    cross.buildPackages.tcl
  ];
  postgresqlTargetTools = builtins.map toString [
    cross.pkgs.bison
    cross.pkgs.flex
    cross.pkgs.gettext
    cross.pkgs.libxml2
    cross.pkgs.libxslt
    cross.pkgs.llvm
    cross.pkgs.perl
    cross.pkgs.pkg-config
    cross.pkgs.python3
    cross.pkgs.tcl
  ];
  systemImageFixture = cross.pkgs.aos-system-image-e2e-fixture;
  compilerRuntimeDirectory = "${cross.stdenv.gcc}/${cross.stdenv.hostPlatform.config}/lib64";
  foundationPackageNames = [
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "findutils"
    "gawk"
    "diffutils"
    "tar"
    "gzip"
    "patch"
  ];
  targetFoundationPackages = builtins.map (name: cross.pkgs.${name}) foundationPackageNames;
  buildFoundationPackages = builtins.map (name: cross.buildPackages.${name}) foundationPackageNames;
  targetFoundationPaths = builtins.map toString targetFoundationPackages;
  foundationRoles = pkgs.lib.zipLists targetFoundationPackages buildFoundationPackages;
  qemuSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  qemuUser = cross.buildPackages.qemu-aarch64-linux-user;
  targetRunner = cross.stdenv.targetRunner;
  targetLinuxHeaders = cross.pkgs.linux-headers;

  targetRuntimeFixture = cross.stdenv.mkDerivation {
    pname = "linux-cross-target-runtime-fixture";
    version = "0";
    src = null;
    runtimeDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib/pkgconfig"
          printf 'target runtime tool\n' > "$out/bin/target-runtime-tool"
          chmod +x "$out/bin/target-runtime-tool"
          printf '#define AOS_TARGET_RUNTIME_FIXTURE 1\n' > "$out/include/target-runtime-fixture.h"
          printf 'target runtime library\n' > "$out/lib/libtarget-runtime-fixture.so"
          printf 'Name: target-runtime-fixture\nVersion: 0\n' \
            > "$out/lib/pkgconfig/target-runtime-fixture.pc"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };

  nativeBuildToolFixture = pkgs.stdenv.mkDerivation {
    pname = "linux-cross-native-build-tool-fixture";
    version = "0";
    src = null;
    runtimeDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib"
          printf '%s\n' \
            '#!${pkgs.bash}/bin/bash' \
            'printf "native build tool\\n"' \
            > "$out/bin/native-build-tool"
          chmod +x "$out/bin/native-build-tool"
          printf 'native build library\n' > "$out/lib/libnative-build-tool.so"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };

  dependencyRoleProbe = cross.stdenv.mkDerivation {
    pname = "linux-cross-dependency-role-probe";
    version = "0";
    src = null;
    buildDeps = [nativeBuildToolFixture];
    runtimeDeps = [targetRuntimeFixture];
    phases = [
      {
        name = "check";
        script = ''
          test "$(command -v native-build-tool)" = \
            "${nativeBuildToolFixture}/bin/native-build-tool"
          test "$(native-build-tool)" = "native build tool"

          case ":$PATH:" in
            *":${targetRuntimeFixture}/bin:"*)
              echo "target runtime executable leaked into cross-build PATH" >&2
              exit 1
              ;;
          esac
          case ":$LD_LIBRARY_PATH:" in
            *":${targetRuntimeFixture}/lib:"*)
              echo "target runtime library leaked into native loader path" >&2
              exit 1
              ;;
          esac
          case ":$C_INCLUDE_PATH:" in
            *":${targetRuntimeFixture}/include:"*) ;;
            *)
              echo "target runtime headers missing from cross compiler path" >&2
              exit 1
              ;;
          esac
          case ":$CPLUS_INCLUDE_PATH:" in
            *":${targetRuntimeFixture}/include:"*) ;;
            *)
              echo "target runtime headers missing from C++ cross compiler path" >&2
              exit 1
              ;;
          esac
          case ":$LIBRARY_PATH:" in
            *":${targetRuntimeFixture}/lib:"*) ;;
            *)
              echo "target runtime library missing from cross linker path" >&2
              exit 1
              ;;
          esac
          case ":$LD_LIBRARY_PATH:" in
            *":${nativeBuildToolFixture}/lib:"*) ;;
            *)
              echo "native build library missing from native loader path" >&2
              exit 1
              ;;
          esac
          case ":$PKG_CONFIG_PATH:" in
            *":${targetRuntimeFixture}/lib/pkgconfig:"*) ;;
            *)
              echo "target runtime metadata missing from pkg-config path" >&2
              exit 1
              ;;
          esac
          case " $NIX_LDFLAGS " in
            *" -Wl,-rpath,${compilerRuntimeDirectory} "*) ;;
            *)
              echo "compiler runtime missing from default cross linker flags" >&2
              exit 1
              ;;
          esac
          case " $NIX_LDFLAGS " in
            *" -Wl,-rpath,${targetRuntimeFixture}/lib "*) ;;
            *)
              echo "runtime dependency missing from default cross linker flags" >&2
              exit 1
              ;;
          esac

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };

  explicitLinkerFlagsProbe = cross.stdenv.mkDerivation {
    pname = "linux-cross-explicit-linker-flags-probe";
    version = "0";
    src = null;
    runtimeDeps = [targetRuntimeFixture];
    NIX_LDFLAGS = "-Wl,--as-needed";
    phases = [
      {
        name = "check";
        script = ''
          case " $NIX_LDFLAGS " in
            *" -Wl,-rpath,${compilerRuntimeDirectory} "*) ;;
            *)
              echo "compiler runtime missing from explicit cross linker flags" >&2
              exit 1
              ;;
          esac
          case " $NIX_LDFLAGS " in
            *" -Wl,--as-needed "*) ;;
            *)
              echo "explicit cross linker flag was not preserved" >&2
              exit 1
              ;;
          esac
          case " $NIX_LDFLAGS " in
            *"${targetRuntimeFixture}"*)
              echo "runtime dependency leaked into explicit cross linker flags" >&2
              exit 1
              ;;
          esac

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
  };
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.system == targetSystem;
  assert cross.stdenv.cc.system == buildSystem;
  assert cross.stdenv.gcc.system == buildSystem;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert cross.stdenv.hostPlatform.pageSize == 4096;
  assert cross.buildPackages.rust.system == buildSystem;
  # Crucible's Rust, pkg-config, and protobuf executables are build tools even
  # when the suite's runtime artifacts target AArch64.
  assert crucible.platforms.host.system == targetSystem;
  assert crucible.system == buildSystem;
  # Locale data targets AArch64, but localedef must remain executable on the
  # build machine while consuming the target libc's matching i18n sources.
  assert glibcLocales.platforms.host.system == targetSystem;
  assert glibcLocales.system == buildSystem;
  assert builtins.elem (toString cross.buildPackages.glibc.bin) glibcLocales.nativeBuildInputs;
  assert !(builtins.elem (toString cross.pkgs.glibc.bin) glibcLocales.nativeBuildInputs);
  assert passt.platforms.host.system == targetSystem;
  assert passt.system == buildSystem;
  assert !(builtins.elem (toString cross.pkgs.glibc.bin) passt.nativeBuildInputs);
  # PostgreSQL's generators execute on the build host while its language,
  # LLVM/JIT, and extension interfaces remain target-side.
  assert postgresql.platforms.host.system == targetSystem;
  assert postgresql.system == buildSystem;
  assert postgresql.configureFlags == "--build=x86_64-unknown-linux-gnu --host=aarch64-unknown-linux-gnu ";
  assert builtins.all (tool: builtins.elem tool postgresql.buildInputs) postgresqlTargetTools;
  assert builtins.all (tool: !(builtins.elem tool postgresql.nativeBuildInputs)) postgresqlTargetTools;
  assert builtins.all (tool: pkgs.lib.hasInfix tool postgresqlBuildScript) postgresqlBuildDrivers;
  assert pkgs.lib.hasInfix "${cross.buildPackages.llvm}/bin/clang --target=${cross.stdenv.hostPlatform.config}" postgresqlBuildScript;
  assert pkgs.lib.hasInfix "${cross.buildPackages.python3}/bin/python3" postgresqlBuildScript;
  assert pkgs.lib.hasInfix "${cross.pkgs.python3}/lib" postgresqlBuildScript;
  # Public runtime roots are target packages, while their build dependencies
  # remain executable on the build machine.
  assert builtins.all (role: role.fst.platforms.host.system == targetSystem) foundationRoles;
  assert builtins.all (role: role.fst.system == buildSystem) foundationRoles;
  assert builtins.all (role: role.fst.drvPath != role.snd.drvPath) foundationRoles;
  assert builtins.all (
    package:
      builtins.all (input: !(builtins.elem (toString input) targetFoundationPaths))
      package.nativeBuildInputs
  )
  targetFoundationPackages;
  # The Linux-user emulator is an explicit native build tool, not a public
  # AArch64 package or a Crucible-patched system emulator.
  assert !(cross.pkgs ? qemu-aarch64-linux-user);
  assert cross.buildPackages ? qemu-aarch64-linux-user;
  assert qemuUser.system == buildSystem;
  assert qemuUser.platforms.host.system == buildSystem;
  assert qemuUser.version == qemuSeries.qemuVersion;
  assert qemuUser.src.outputHash == qemuSeries.qemuSourceHash;
  assert qemuUser.passthru.targetList == "aarch64-linux-user";
  assert !(qemuUser.passthru.crucibleIntegration);
  assert builtins.elem "--disable-system" qemuUser.passthru.configureFlags;
  assert builtins.elem "--disable-plugins" qemuUser.passthru.configureFlags;
  assert builtins.elem "--disable-tools" qemuUser.passthru.configureFlags;
  assert !(builtins.elem "--enable-plugins" qemuUser.passthru.configureFlags);
  assert targetRunner != null;
  assert targetRunner.system == buildSystem;
  # Evaluating the x86-specific image fixture under a target package set must
  # keep its data artifacts targeted while every derivation runs on the build
  # platform. This catches target data accidentally classified as buildDeps.
  assert systemImageFixture.platforms.host.system == targetSystem;
  assert systemImageFixture.system == buildSystem;
    cross.stdenv.mkDerivation {
      pname = "linux-cross-smoke-aarch64";
      version = "0";
      src = null;
      runtimeDeps = [cross.pkgs.krb5];

      phases = [
        {
          name = "build-and-verify";
          script = ''
            fail() {
              echo "linux-cross-smoke: FAIL: $*" >&2
              exit 1
            }

            check() {
              description=$1
              shift
              "$@" || fail "$description"
            }

            check_contains() {
              description=$1
              pattern=$2
              path=$3

              grep -Fq -- "$pattern" "$path" || fail "$description"
            }

            check_line() {
              description=$1
              line=$2
              path=$3

              grep -Fxq -- "$line" "$path" || fail "$description"
            }

            check_group() {
              echo "linux-cross-smoke: checking $1" >&2
            }

            mkdir -p "$out/bin"

            check_group 'runner and dependency configuration'
            check 'dependency role probe did not pass' \
              test "$(cat ${dependencyRoleProbe}/result)" = PASS
            check 'explicit linker flags probe did not pass' \
              test "$(cat ${explicitLinkerFlagsProbe}/result)" = PASS
            runner=${targetRunner}/bin/aos-run-${targetSystem}
            check 'target runner is not executable' test -x "$runner"
            qemu_identity=${qemuUser}/share/aos/qemu-user/build-identity.env
            check_line 'QEMU version identity is incorrect' \
              'qemu_version=${qemuSeries.qemuVersion}' "$qemu_identity"
            check_line 'QEMU source identity is incorrect' \
              'qemu_source_hash=${qemuSeries.qemuSourceHash}' "$qemu_identity"
            check_line 'QEMU target list is incorrect' \
              'qemu_configure_target_list=aarch64-linux-user' "$qemu_identity"
            check_line 'QEMU plugins must remain disabled' \
              'qemu_plugins_enabled=false' "$qemu_identity"
            check_line 'QEMU tools must remain disabled' \
              'qemu_tools_enabled=false' "$qemu_identity"
            check_line 'QEMU Crucible patches must remain absent' \
              'qemu_crucible_patches_applied=false' "$qemu_identity"
            check_line 'QEMU system emulation must remain disabled' \
              'qemu_system_emulation_enabled=false' "$qemu_identity"
            check_contains 'Meson target runner is incorrect' \
              "exe_wrapper = '$runner'" \
              ${cross.stdenv.stdenv}/meson-cross.ini
            printf '%s\n' "$cmakeFlags" > cmake-flags
            check_contains 'CMake target runner is incorrect' \
              "-DCMAKE_CROSSCOMPILING_EMULATOR=$runner" cmake-flags

            verify_target_program() {
              label=$1
              executable=$2

              test -x "$executable" || {
                echo "$label target executable is missing: $executable" >&2
                exit 1
              }
              if ! ${cross.stdenv.binutils}/bin/readelf -h "$executable" | \
                grep -Fq 'Machine:                           AArch64'; then
                fail "$label target is not an AArch64 ELF: $executable"
              fi
              if ! ${cross.stdenv.binutils}/bin/readelf -l "$executable" | \
                grep -Fq '${cross.stdenv.glibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}'; then
                fail "$label target has the wrong interpreter: $executable"
              fi
            }

            check_group 'target foundation artifacts'
            verify_target_program bash ${cross.pkgs.bash}/bin/bash
            verify_target_program coreutils ${cross.pkgs.coreutils}/bin/coreutils
            verify_target_program gnumake ${cross.pkgs.gnumake}/bin/make
            verify_target_program sed ${cross.pkgs.sed}/bin/sed
            verify_target_program grep ${cross.pkgs.grep}/bin/grep
            verify_target_program findutils ${cross.pkgs.findutils}/bin/find
            verify_target_program gawk ${cross.pkgs.gawk}/bin/gawk
            verify_target_program diffutils ${cross.pkgs.diffutils}/bin/diff
            verify_target_program tar ${cross.pkgs.tar}/bin/tar
            verify_target_program gzip ${cross.pkgs.gzip}/bin/gzip
            verify_target_program patch ${cross.pkgs.patch}/bin/patch

            check 'target zgrep does not use target Bash' \
              test "$(head -n 1 ${cross.pkgs.gzip}/bin/zgrep)" = \
                '#!${cross.pkgs.bash}/bin/bash'
            set +e
            grep -RIl \
              '^#!${cross.buildPackages.bash}/bin/bash$' \
              ${builtins.concatStringsSep " " targetFoundationPaths} \
              > native-foundation-shebangs
            native_shebang_status=$?
            set -e
            case "$native_shebang_status" in
              0)
                echo 'native Bash shebang leaked into target packages:' >&2
                cat native-foundation-shebangs >&2
                exit 1
                ;;
              1) ;;
              *) fail "native Bash shebang scan failed with status $native_shebang_status" ;;
            esac

            check 'target glibc UTF-8 charmap is missing' \
              test -f '${cross.pkgs.glibc.bin}/share/i18n/charmaps/UTF-8.gz'
            check 'target glibc C locale is missing' \
              test -f '${cross.pkgs.glibc.bin}/share/i18n/locales/C'

            check_group 'target compilation and linkage'
            printf '%s\n' \
              '#include <stdio.h>' \
              'int main(void) { return puts("aos Linux C cross smoke") < 0; }' \
              > smoke.c
            "$CC" smoke.c -o "$out/bin/aos-linux-c-smoke"

            printf '%s\n' \
              '#include <sys/syscall.h>' \
              '#ifndef __aarch64__' \
              '#error "cross compiler did not select AArch64"' \
              '#endif' \
              '#if __NR_gettid != 178' \
              '#error "cross compiler selected non-AArch64 syscall headers"' \
              '#endif' \
              'int main(void) { return __NR_gettid == 178 ? 0 : 1; }' \
              > syscall-header-smoke.c
            "$CC" -I${targetLinuxHeaders}/include syscall-header-smoke.c \
              -o "$out/bin/aos-linux-syscall-header-smoke"

            printf '%s\n' \
              '#include <iostream>' \
              'int main() { std::cout << "aos Linux C++ cross smoke\\n"; return 0; }' \
              > smoke.cc
            "$CXX" smoke.cc -o "$out/bin/aos-linux-cxx-smoke"

            pie_disabled_hardening=""
            for token in $AOS_HARDENING_ENABLE; do
              if test "$token" != pie; then
                pie_disabled_hardening="''${pie_disabled_hardening}''${pie_disabled_hardening:+ }$token"
              fi
            done
            AOS_HARDENING_ENABLE="$pie_disabled_hardening" \
              "$CC" smoke.c -o "$out/bin/aos-linux-c-smoke-no-pie"

            "$CC" -fPIC -shared smoke.c -o "$out/liblinux-cross-smoke.so"
            "$CC" -c smoke.c -o smoke.o
            "$CC" -r smoke.o -o "$out/linux-cross-smoke-relocatable.o"

            mkdir -p "$out/bin/origin"
            "$CC" -fPIC -shared ${./linux-cross-origin-library.c} \
              -Wl,-soname,liblinux-cross-origin.so \
              -o "$out/bin/origin/liblinux-cross-origin.so"
            "$CC" ${./linux-cross-origin-probe.c} \
              -L"$out/bin/origin" \
              -Wl,-rpath,'$ORIGIN' \
              -llinux-cross-origin \
              -o "$out/bin/origin/linux-cross-origin-probe"

            "$CC" ${./linux-cross-runner-probe.c} \
              -o "$out/bin/linux-cross-runner-dynamic"
            "$CC" -static ${./linux-cross-runner-probe.c} \
              -o "$out/bin/linux-cross-runner-static"
            "$CC" ${./linux-cross-runner-thread.c} -pthread \
              -o "$out/bin/linux-cross-runner-thread"

            "$CC" -fPIC -shared ${./linux-cross-export-module.c} \
              -o "$out/liblinux-cross-export-module.so"
            "$CC" ${./linux-cross-export-main.c} -ldl \
              -Wl,--export-dynamic \
              -o "$out/bin/linux-cross-export-dynamic"
            "$CC" ${./linux-cross-export-main.c} -ldl \
              -o "$out/bin/linux-cross-export-default"

            verify_runner_probe() {
              executable=$1
              output=$2

              # Meson and CMake hand their executable linker outputs to the
              # runner. Keep that Linux execution contract explicit.
              check "runner probe is not executable: $executable" \
                test -x "$executable"
              set +e
              QEMU_ARGV0='ambient argv zero' \
              QEMU_LD_PREFIX=/ambient/target/prefix \
              QEMU_SET_ENV='LD_LIBRARY_PATH=/ambient/target/lib' \
              QEMU_VERSION=1 \
              "$runner" "$executable" \
                'first argument' 'second argument' > "$output"
              status=$?
              set -e

              check "runner probe returned $status instead of 37: $executable" \
                test "$status" -eq 37
              check "runner probe output is incorrect: $executable" \
                test "$(cat "$output")" = 'AOS cross runner probe passed'
            }

            check_group 'target execution and runner rejection'
            verify_runner_probe \
              "$out/bin/linux-cross-runner-dynamic" dynamic-runner.out
            verify_runner_probe \
              "$out/bin/linux-cross-runner-static" static-runner.out
            "$runner" "$out/bin/aos-linux-syscall-header-smoke"
            "$runner" "$out/bin/linux-cross-runner-thread" \
              > thread-runner.out
            check 'runner thread probe output is incorrect' \
              test "$(cat thread-runner.out)" = \
                'AOS cross runner thread probe passed'

            "$runner" "$out/bin/linux-cross-export-dynamic" \
              "$out/liblinux-cross-export-module.so"
            set +e
            "$runner" "$out/bin/linux-cross-export-default" \
              "$out/liblinux-cross-export-module.so" \
              >/dev/null 2>export-default.err
            export_default_status=$?
            set -e
            check 'backend without --export-dynamic did not reject extension symbol' \
              test "$export_default_status" -eq 1
            check_contains 'missing backend symbol diagnostic is absent' \
              'undefined symbol: aos_cross_exported_symbol' export-default.err

            "$runner" "$out/bin/origin/linux-cross-origin-probe" \
              > origin-runner.out
            check 'runner did not preserve target executable identity' \
              test "$(cat origin-runner.out)" = \
                'AOS cross runner origin probe passed'
            ${cross.stdenv.binutils}/bin/readelf -d \
              "$out/bin/origin/linux-cross-origin-probe" \
              > origin-dynamic-section
            if ! grep -Eq 'Library (rpath|runpath): \[\$ORIGIN(:|\])' \
              origin-dynamic-section; then
              fail 'origin probe does not begin its RPATH/RUNPATH with $ORIGIN'
            fi

            cp "$out/bin/linux-cross-runner-dynamic" non-executable-target
            chmod 0644 non-executable-target
            set +e
            "$runner" non-executable-target \
              >/dev/null 2>non-executable.err
            non_executable_status=$?
            set -e
            check 'non-executable target did not return runner status 67' \
              test "$non_executable_status" -eq 67
            check_contains 'non-executable target diagnostic is missing' \
              'target is not executable' non-executable.err

            set +e
            "$runner" ${pkgs.coreutils}/bin/coreutils >/dev/null 2>wrong-machine.err
            wrong_machine_status=$?
            set -e
            check 'wrong-machine target did not return runner status 65' \
              test "$wrong_machine_status" -eq 65
            check_contains 'wrong-machine target diagnostic is missing' \
              'rejected a non-AArch64 ELF target' wrong-machine.err

            set +e
            "$runner" >/dev/null 2>missing-argument.err
            missing_argument_status=$?
            "$runner" "$PWD/does-not-exist" >/dev/null 2>missing-file.err
            missing_file_status=$?
            set -e
            check 'missing runner argument did not return status 64' \
              test "$missing_argument_status" -eq 64
            check_contains 'missing runner argument usage is absent' \
              'usage:' missing-argument.err
            check 'missing target did not return runner status 66' \
              test "$missing_file_status" -eq 66
            check_contains 'missing target diagnostic is absent' \
              'not a regular file' missing-file.err

            check_group 'configure-time execution probes'
            "$CC" ${./krb5-constructor-destructor-probe.c} \
              -o "$out/bin/krb5-constructor-destructor-probe"
            "$CC" ${./krb5-printf-positional-probe.c} \
              -o "$out/bin/krb5-printf-positional-probe"
            "$CC" ${./krb5-spnego-probe.c} -lgssapi_krb5 \
              -o "$out/bin/krb5-spnego-probe"

            touch conftest.1 conftest.2
            "$runner" "$out/bin/krb5-constructor-destructor-probe"
            check 'constructor probe did not remove conftest.1' \
              test ! -e conftest.1
            check 'destructor probe did not remove conftest.2' \
              test ! -e conftest.2
            "$runner" "$out/bin/krb5-printf-positional-probe"
            "$runner" "$out/bin/krb5-spnego-probe" > krb5-spnego.out
            check 'target GSSAPI library did not advertise SPNEGO' \
              test "$(cat krb5-spnego.out)" = \
                'AOS target GSSAPI SPNEGO probe passed'

            check_group 'ELF type and runtime contracts'
            for executable in \
              "$out/bin/aos-linux-c-smoke" \
              "$out/bin/aos-linux-syscall-header-smoke" \
              "$out/bin/aos-linux-cxx-smoke" \
              "$out/bin/aos-linux-c-smoke-no-pie" \
              "$out/bin/linux-cross-runner-dynamic" \
              "$out/bin/linux-cross-runner-thread" \
              "$out/bin/linux-cross-export-dynamic" \
              "$out/bin/linux-cross-export-default" \
              "$out/bin/krb5-constructor-destructor-probe" \
              "$out/bin/krb5-printf-positional-probe" \
              "$out/bin/krb5-spnego-probe"; do
              if ! ${cross.stdenv.binutils}/bin/readelf -h "$executable" | \
                grep -Fq 'Machine:                           AArch64'; then
                fail "compiled output is not AArch64: $executable"
              fi
              if ! ${cross.stdenv.binutils}/bin/readelf -l "$executable" | \
                grep -Fq '${cross.stdenv.glibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}'; then
                fail "compiled output has the wrong interpreter: $executable"
              fi
            done

            for executable in \
              "$out/bin/aos-linux-c-smoke" \
              "$out/bin/aos-linux-cxx-smoke"; do
              if ! ${cross.stdenv.binutils}/bin/readelf -h "$executable" | \
                grep -Eq 'Type:[[:space:]]+DYN'; then
                fail "default executable is not PIE: $executable"
              fi
            done
            if ! ${cross.stdenv.binutils}/bin/readelf -h \
              "$out/bin/aos-linux-c-smoke-no-pie" | \
              grep -Eq 'Type:[[:space:]]+EXEC'; then
              fail 'PIE-disabled executable is not ET_EXEC'
            fi
            if ! ${cross.stdenv.binutils}/bin/readelf -h \
              "$out/liblinux-cross-smoke.so" | \
              grep -Eq 'Type:[[:space:]]+DYN'; then
              fail 'shared library is not ET_DYN'
            fi
            if ! ${cross.stdenv.binutils}/bin/readelf -h \
              "$out/linux-cross-smoke-relocatable.o" | \
              grep -Eq 'Type:[[:space:]]+REL'; then
              fail 'relocatable link output is not ET_REL'
            fi

            ${cross.stdenv.binutils}/bin/readelf -h \
              "$out/bin/linux-cross-runner-static" | \
              grep -Fq 'Machine:                           AArch64'
            ${cross.stdenv.binutils}/bin/readelf -l \
              "$out/bin/linux-cross-runner-static" \
              > static-runner-program-headers
            if grep -Fq INTERP static-runner-program-headers; then
              fail 'static runner probe unexpectedly has an interpreter'
            fi

            if ! ${cross.stdenv.binutils}/bin/readelf -SW \
              "$out/bin/krb5-constructor-destructor-probe" | \
              grep -Fq '.init_array'; then
              fail 'constructor probe is missing .init_array'
            fi
            if ! ${cross.stdenv.binutils}/bin/readelf -SW \
              "$out/bin/krb5-constructor-destructor-probe" | \
              grep -Fq '.fini_array'; then
              fail 'destructor probe is missing .fini_array'
            fi

            ${cross.stdenv.binutils}/bin/readelf -d \
              "$out/bin/aos-linux-cxx-smoke" > cxx-dynamic-section
            check_contains 'C++ output does not depend on target libstdc++' \
              'Shared library: [libstdc++.so.6]' cxx-dynamic-section
            check_contains 'C++ output does not retain the compiler runtime path' \
              '${compilerRuntimeDirectory}' cxx-dynamic-section

            echo 'linux-cross-smoke: PASS' >&2
          '';
        }
      ];
    }
