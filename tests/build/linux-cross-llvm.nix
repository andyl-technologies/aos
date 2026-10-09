# Installed-toolchain qualification for Linux-hosted AArch64 LLVM.
{pkgs}: let
  lib = pkgs.lib;
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  llvm = cross.pkgs.llvm;
  targetTriple = cross.stdenv.hostPlatform.config;
  targetGcc = cross.stdenv.gcc;
  targetLibc = cross.stdenv.glibc;
  targetBinutils = cross.stdenv.binutils;
  targetKernel = cross.pkgs.linux;
  targetKmod = cross.pkgs.kmod;
  llvmProbeSource = "${./linux-cross-llvm-probe.cpp}";
  runnerProbeSource = "${./linux-cross-runner-probe.c}";
  compilerRuntimeDirectory = "${targetGcc}/${targetTriple}/lib64";
  clangConfig = "${llvm}/etc/clang/${targetTriple}.cfg";

  guestInit = cross.pkgs.mkDerivation {
    pname = "linux-cross-llvm-aarch64-guest-init";
    version = "0";
    src = null;
    runtimeDeps = [
      cross.pkgs.bash
      targetKmod
    ];
    hardeningDisable = ["pie"];

    phases = [
      {
        name = "build";
        script = ''
          cat > guest-init.c <<'C'
          #define _DEFAULT_SOURCE

          #include <errno.h>
          #include <stdio.h>
          #include <stdlib.h>
          #include <sys/mount.h>
          #include <sys/reboot.h>
          #include <sys/stat.h>
          #include <sys/wait.h>
          #include <unistd.h>

          static void mount_required(const char *source, const char *target,
                                     const char *type, unsigned long flags,
                                     const char *options) {
            if (mount(source, target, type, flags, options) != 0 && errno != EBUSY) {
              perror(target);
              exit(EXIT_FAILURE);
            }
          }

          static void run_required(const char *path, char *const arguments[]) {
            int status = 0;
            pid_t child = fork();

            if (child < 0) {
              perror("fork");
              exit(EXIT_FAILURE);
            }
            if (child == 0) {
              execv(path, arguments);
              perror(path);
              _exit(EXIT_FAILURE);
            }
            if (waitpid(child, &status, 0) < 0) {
              perror("waitpid");
              exit(EXIT_FAILURE);
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
              fprintf(stderr, "%s exited unsuccessfully\n", path);
              exit(EXIT_FAILURE);
            }
          }

          int main(void) {
            char *modprobe_9p[] = {"modprobe", "9p", NULL};
            char *modprobe_9p_virtio[] = {"modprobe", "9pnet_virtio", NULL};
            int child_succeeded = 0;
            int status = 0;
            pid_t child;

            mount_required("proc", "/proc", "proc", 0, NULL);
            mount_required("sysfs", "/sys", "sysfs", 0, NULL);
            mount_required("devtmpfs", "/dev", "devtmpfs", 0, NULL);

            run_required("${targetKmod}/sbin/modprobe", modprobe_9p);
            run_required("${targetKmod}/sbin/modprobe", modprobe_9p_virtio);

            mount_required("aos-store", "/nix/store", "9p", MS_RDONLY,
                           "trans=virtio,version=9p2000.L,msize=1048576,cache=none");
            mount_required("aos-output", "/output", "9p", 0,
                           "trans=virtio,version=9p2000.L,msize=1048576,cache=none");

            child = fork();
            if (child < 0) {
              perror("fork");
            } else if (child == 0) {
              execl("${cross.pkgs.bash}/bin/bash", "bash", "/run-tests",
                    (char *)NULL);
              perror("bash");
              _exit(EXIT_FAILURE);
            } else if (waitpid(child, &status, 0) < 0) {
              perror("waitpid");
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
              child_succeeded = 1;
            }

            if (child_succeeded) {
              puts("LLVM_GUEST_RESULT:PASS");
            } else {
              puts("LLVM_GUEST_RESULT:FAIL");
            }
            fflush(NULL);
            sync();
            reboot(RB_POWER_OFF);
            return child_succeeded ? EXIT_SUCCESS : EXIT_FAILURE;
          }
          C

          mkdir -p "$out/bin"
          $CC guest-init.c -o "$out/bin/guest-init"
        '';
      }
    ];
  };

  guestClosureDeps = [
    guestInit
    targetKernel
    targetKmod
  ];
  guestClosureGraph =
    lib.concatLists
    (lib.imap (index: dependency: [
        "guest-closure-${builtins.toString index}"
        dependency
      ])
      guestClosureDeps);
  guestExecutionInputs = [
    llvmProbeSource
    runnerProbeSource
    cross.pkgs.bash
    cross.pkgs.coreutils
    cross.pkgs.glibc.dev
    cross.pkgs.grep
    cross.pkgs.sed
    guestInit
    llvm
    targetGcc
    targetKernel
    targetKmod
    targetLibc
  ];
  guestExecutionRoots = builtins.concatStringsSep "\n" (map toString guestExecutionInputs);

  guestInitramfs = pkgs.mkDerivation {
    pname = "linux-cross-llvm-aarch64-guest-initramfs";
    version = "0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.cpio
      pkgs.findutils
      pkgs.pigz
    ];
    exportReferencesGraph = guestClosureGraph;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          grep -h '^/nix/store/' guest-closure-* | sort -u > closure-paths

          mkdir -p root/bin root/dev root/lib root/nix/store root/output root/proc root/sys root/tmp
          while IFS= read -r path; do
            cp -a "$path" root"$path"
          done < closure-paths

          chmod 1777 root/tmp
          ln -s ${targetKernel}/lib/modules root/lib/modules
          cp ${guestInit}/bin/guest-init root/init
          cat > root/run-tests <<'TESTS'
          set -eu
          export HOME=/tmp
          export LC_ALL=C
          export PATH="${cross.pkgs.coreutils}/bin:${cross.pkgs.grep}/bin:${cross.pkgs.sed}/bin"
          export TMPDIR=/tmp

          work_directory=/tmp/linux-cross-llvm
          mkdir -p "$work_directory"
          cd "$work_directory"

          uname -m
          test "$(uname -m)" = aarch64

          # No target, sysroot, include, library, runtime, dynamic-linker, or
          # linker flags are supplied. The installed target compiler and its
          # triple-specific configuration must be complete on their own.
          ${llvm}/bin/clang -v \
            ${runnerProbeSource} \
            -o /output/linux-cross-runner-llvm \
            2> /output/clang-c.trace
          ${llvm}/bin/clang++ -v \
            ${llvmProbeSource} \
            -o /output/linux-cross-llvm-cxx \
            2> /output/clang-cxx.trace
          ${llvm}/bin/clang++ -v \
            -Wl,--as-needed -fno-exceptions \
            ${llvmProbeSource} \
            -o /output/linux-cross-llvm-cxx-as-needed \
            2> /output/clang-cxx-as-needed.trace

          set +e
          /output/linux-cross-runner-llvm \
            'first argument' 'second argument' > /output/c-run.out
          c_status=$?
          set -e
          test "$c_status" -eq 37
          test "$(cat /output/c-run.out)" = 'AOS cross runner probe passed'

          for executable in \
            /output/linux-cross-llvm-cxx \
            /output/linux-cross-llvm-cxx-as-needed; do
            "$executable" > /output/cxx-run.out
            test "$(cat /output/cxx-run.out)" = \
              'AOS automatic Clang C++ config passed: 10'
          done

          echo aarch64 > /output/guest-machine
          TESTS
          chmod 0755 root/init root/run-tests

          mkdir -p "$out"
          cat > "$out/guest-store-roots" <<'ROOTS'
          ${guestExecutionRoots}
          ROOTS
          (
            cd root
            find . -print0 \
              | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | pigz -9 -n -p "''${NIX_BUILD_CORES:-1}" > "$out/initrd.img"
          )
          test -s "$out/initrd.img"
        '';
      }
    ];
  };
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert llvm.platforms.host.system == targetSystem;
  assert llvm.system == buildSystem;
    cross.stdenv.mkDerivation {
      pname = "linux-cross-llvm-aarch64";
      version = "0";
      src = null;
      requiredSystemFeatures = ["kvm"];
      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.grep
        pkgs.patchelf
        pkgs.qemu
        pkgs.sed
      ];

      phases = [
        {
          name = "qualify-installed-toolchain";
          script = ''
            fail() {
              echo "linux-cross-llvm: FAIL: $*" >&2
              exit 1
            }

            check_contains() {
              description=$1
              pattern=$2
              path=$3

              grep -Fq -- "$pattern" "$path" || fail "$description"
            }

            check_absent() {
              description=$1
              pattern=$2
              path=$3

              if grep -Fq -- "$pattern" "$path"; then
                fail "$description"
              fi
            }

            extract_guest_results() {
              path=$1
              output=$2

              {
                grep -Eo 'LLVM_GUEST_RESULT:(PASS|FAIL)(\[|[[:space:]]|$)' "$path" || true
              } | sed -e 's/\[$//' -e 's/[[:space:]]$//' > "$output"
            }

            guest_result_is_pass() {
              path=$1
              output=$2

              extract_guest_results "$path" "$output"
              test "$(wc -l < "$output")" -eq 1 && \
                test "$(cat "$output")" = 'LLVM_GUEST_RESULT:PASS'
            }

            check_guest_result_case() {
              expected=$1
              description=$2
              shift 2

              printf '%s\n' "$@" > guest-result-case
              if guest_result_is_pass guest-result-case guest-result-case-matches; then
                actual=accepted
              else
                actual=rejected
              fi
              test "$actual" = "$expected" || \
                fail "guest-result matcher mishandled $description"
            }

            check_aarch64() {
              description=$1
              path=$2

              ${targetBinutils}/bin/readelf -hW "$path" > elf-header
              check_contains "$description is not an AArch64 ELF" \
                'Machine:                           AArch64' elf-header
            }

            check_interpreter() {
              description=$1
              path=$2

              ${targetBinutils}/bin/readelf -lW "$path" > program-headers
              check_contains "$description has the wrong interpreter" \
                '${targetLibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}' \
                program-headers
            }

            check_dynamic() {
              path=$1
              output=$2

              ${targetBinutils}/bin/readelf -dW "$path" > "$output"
            }

            check_needed_set() {
              description=$1
              path=$2
              shift 2

              ${targetBinutils}/bin/readelf -dW "$path" | \
                sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | \
                sort > actual-needed
              : > expected-needed
              if test "$#" -gt 0; then
                printf '%s\n' "$@" | sort > expected-needed
              fi
              if ! cmp -s expected-needed actual-needed; then
                echo "$description has an unexpected NEEDED set" >&2
                diff -u expected-needed actual-needed >&2 || true
                exit 1
              fi
            }

            check_runpath() {
              description=$1
              path=$2
              expected=$3
              actual=$(${cross.buildPackages.patchelf}/bin/patchelf \
                --print-rpath "$path")

              test "$actual" = "$expected" || \
                fail "$description has an unexpected RPATH: $actual"
            }

            check_no_runpath() {
              description=$1
              path=$2

              check_dynamic "$path" no-runpath-dynamic
              if grep -E '\((RPATH|RUNPATH)\)' no-runpath-dynamic >/dev/null; then
                fail "$description unexpectedly has an RPATH or RUNPATH"
              fi
            }

            test -f ${clangConfig} || fail 'installed Clang config is missing'
            set -- ${targetGcc}/lib/gcc/${targetTriple}/*
            if test "$#" -ne 1 || test ! -d "$1"; then
              fail 'target GCC install directory is ambiguous or missing'
            fi
            gccInstallDirectory=$1

            check_contains 'Clang config does not select the target GCC install' \
              "--gcc-install-dir=$gccInstallDirectory" ${clangConfig}
            check_contains 'Clang config does not select the target libc headers' \
              '${cross.pkgs.glibc.dev}/include' ${clangConfig}
            check_contains 'Clang config does not select the installed target linker' \
              '-fuse-ld=${llvm}/bin/ld.lld' ${clangConfig}
            check_absent 'Clang config retains a build-directory path' \
              '/build/' ${clangConfig}
            check_absent 'Clang config retains the native LLVM toolchain' \
              '${cross.buildPackages.llvm}' ${clangConfig}

            check_guest_result_case accepted clean-pass \
              'LLVM_GUEST_RESULT:PASS'
            check_guest_result_case accepted interleaved-pass \
              'LLVM_GUEST_RESULT:PASS[   35.0] kernel message'
            check_guest_result_case rejected fail \
              'LLVM_GUEST_RESULT:FAIL'
            check_guest_result_case rejected duplicate-pass \
              'LLVM_GUEST_RESULT:PASS' 'LLVM_GUEST_RESULT:PASS'
            check_guest_result_case rejected mixed-pass-fail \
              'LLVM_GUEST_RESULT:PASS' 'LLVM_GUEST_RESULT:FAIL'
            check_guest_result_case rejected missing \
              'ordinary serial output'
            check_guest_result_case rejected malformed \
              'LLVM_GUEST_RESULT:PASSjunk'

            serial="$TMPDIR/serial.log"
            guestOutput="$TMPDIR/guest-output"
            mkdir -p "$guestOutput" "$out/bin"

            set +e
            timeout 600 ${pkgs.qemu}/bin/qemu-system-aarch64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine virt,gic-version=2 \
              -cpu cortex-a57 \
              -accel tcg \
              -m 4096 \
              -smp 1 \
              -kernel ${targetKernel}/boot/vmlinuz-${targetKernel.version} \
              -initrd ${guestInitramfs}/initrd.img \
              -append 'console=ttyAMA0 rdinit=/init panic=-1' \
              -fsdev local,id=aos_store,path=/nix/store,security_model=none,readonly=on \
              -device virtio-9p-pci,fsdev=aos_store,mount_tag=aos-store \
              -fsdev local,id=aos_output,path="$guestOutput",security_model=none \
              -device virtio-9p-pci,fsdev=aos_output,mount_tag=aos-output \
              -serial stdio \
              -no-reboot \
              > "$serial" 2>&1
            qemuStatus=$?
            set -e
            sed -i 's/\r$//' "$serial"
            cat "$serial"

            if test "$qemuStatus" -eq 124; then
              fail 'full-system AArch64 guest timed out'
            fi
            test "$qemuStatus" -eq 0 || \
              fail "full-system AArch64 guest returned $qemuStatus"
            guest_result_is_pass "$serial" guest-results || \
              fail 'full-system AArch64 guest did not report one PASS result'
            check_absent 'full-system AArch64 guest reported failure' \
              'LLVM_GUEST_RESULT:FAIL' "$serial"
            test "$(cat "$guestOutput/guest-machine")" = aarch64 || \
              fail 'full-system guest did not report AArch64'

            for trace in \
              "$guestOutput/clang-c.trace" \
              "$guestOutput/clang-cxx.trace" \
              "$guestOutput/clang-cxx-as-needed.trace"; do
              check_contains 'guest Clang trace omitted its cc1 invocation' \
                '"${llvm}/bin/clang-22" -cc1 ' "$trace"
              check_contains 'guest Clang trace did not execute installed ld.lld' \
                '"${llvm}/bin/ld.lld"' "$trace"
            done

            cp \
              "$guestOutput/linux-cross-runner-llvm" \
              "$guestOutput/linux-cross-llvm-cxx" \
              "$guestOutput/linux-cross-llvm-cxx-as-needed" \
              "$out/bin/"
            cp \
              "$guestOutput/clang-c.trace" \
              "$guestOutput/clang-cxx.trace" \
              "$guestOutput/clang-cxx-as-needed.trace" \
              "$serial" \
              "$out/"

            for executable in \
              ${llvm}/bin/clang-22 \
              ${llvm}/bin/lld \
              "$out/bin/linux-cross-runner-llvm" \
              "$out/bin/linux-cross-llvm-cxx" \
              "$out/bin/linux-cross-llvm-cxx-as-needed"; do
              check_aarch64 'installed LLVM or compiled output' "$executable"
            done
            for executable in \
              "$out/bin/linux-cross-runner-llvm" \
              "$out/bin/linux-cross-llvm-cxx" \
              "$out/bin/linux-cross-llvm-cxx-as-needed"; do
              check_interpreter 'compiled output' "$executable"
            done

            check_dynamic \
              "$out/bin/linux-cross-llvm-cxx-as-needed" \
              as-needed-dynamic
            check_contains 'as-needed C++ output does not depend on libstdc++' \
              'Shared library: [libstdc++.so.6]' as-needed-dynamic
            check_contains 'as-needed C++ output does not depend on target libc' \
              'Shared library: [libc.so.6]' as-needed-dynamic
            check_absent 'as-needed C++ output retained direct libgcc_s' \
              'Shared library: [libgcc_s.so.1]' as-needed-dynamic
            check_contains 'as-needed C++ output lacks the GCC runtime RUNPATH' \
              '${compilerRuntimeDirectory}' as-needed-dynamic
            check_contains 'as-needed C++ output lacks the libc RUNPATH' \
              '${targetLibc}/lib' as-needed-dynamic

            asNeeded="$out/bin/linux-cross-llvm-cxx-as-needed"
            check_needed_set 'as-needed C++ output' "$asNeeded" \
              libstdc++.so.6 libc.so.6
            check_runpath 'as-needed C++ output' "$asNeeded" \
              '${targetLibc}/lib:${targetGcc}/lib:${compilerRuntimeDirectory}'

            libstdcxx=${compilerRuntimeDirectory}/libstdc++.so.6
            libgcc=${compilerRuntimeDirectory}/libgcc_s.so.1
            for runtime in "$libstdcxx" "$libgcc"; do
              test -f "$runtime" || fail "target GCC runtime is missing: $runtime"
              check_aarch64 'target GCC runtime' "$runtime"
            done

            check_dynamic "$libstdcxx" libstdcxx-dynamic
            check_contains 'libstdc++ does not own its sibling runtime RUNPATH' \
              '${compilerRuntimeDirectory}' libstdcxx-dynamic
            check_contains 'libstdc++ does not own its libc RUNPATH' \
              '${targetLibc}/lib' libstdcxx-dynamic
            for dependency in libm.so.6 libgcc_s.so.1 libc.so.6; do
              check_contains "libstdc++ does not depend on $dependency" \
                "Shared library: [$dependency]" libstdcxx-dynamic
            done
            check_needed_set 'target libstdc++' "$libstdcxx" \
              libm.so.6 libc.so.6 libgcc_s.so.1
            check_runpath 'target libstdc++' "$libstdcxx" \
              '${compilerRuntimeDirectory}:${targetLibc}/lib'

            check_dynamic "$libgcc" libgcc-dynamic
            check_contains 'libgcc_s does not own its libc RUNPATH' \
              '${targetLibc}/lib' libgcc-dynamic
            check_contains 'libgcc_s does not depend on libc' \
              'Shared library: [libc.so.6]' libgcc-dynamic
            check_needed_set 'target libgcc_s' "$libgcc" libc.so.6
            check_runpath 'target libgcc_s' "$libgcc" '${targetLibc}/lib'

            libm=${targetLibc}/lib/libm.so.6
            libc=${targetLibc}/lib/libc.so.6
            loader=${targetLibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}
            for runtime in "$libm" "$libc" "$loader"; do
              check_aarch64 'target libc runtime' "$runtime"
              check_no_runpath 'target libc runtime' "$runtime"
            done
            check_needed_set 'target libm' "$libm" libc.so.6
            check_needed_set 'target libc' "$libc" \
              ${cross.stdenv.hostPlatform.dynamicLinker}
            check_needed_set 'target dynamic loader' "$loader"

            printf 'PASS\n' > "$out/result"
            echo 'linux-cross-llvm: PASS' >&2
          '';
        }
      ];

      # The qualification phase already verifies final runtime paths and the
      # output is evidence, not a package awaiting generic ELF mutation.
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
    }
