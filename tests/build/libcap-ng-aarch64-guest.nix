# Full-system AArch64 qualification for libcap-ng's kernel capability API.
{
  lib,
  buildPackages,
  targetPackages,
  payload,
  version,
}: let
  linuxSource = import ../../pkgs/kernel/_source.nix {
    inherit (buildPackages) fetchurl mkManualUpstream;
  };

  kernel = buildPackages.mkDerivation {
    pname = "libcap-ng-aarch64-guest-linux";
    inherit (linuxSource) version src;

    buildDeps = [
      buildPackages."llvm-21"
      buildPackages.bc
      buildPackages.bison
      buildPackages.coreutils
      buildPackages.elfutils
      buildPackages.flex
      buildPackages.gawk
      buildPackages.gnumake
      buildPackages.openssl
      buildPackages.perl
      buildPackages.python3
      buildPackages.rsync
    ];
    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd linux-${linuxSource.version}
          for file in $(find . -type f -name '*.py'); do
            case "$(head -n 1 "$file")" in
              '#!'*python*) sed -i "1s|.*|#!${buildPackages.python3}/bin/python3|" "$file" ;;
            esac
          done
        '';
      }
      {
        name = "configure";
        script = ''
          make ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ tinyconfig
          cat > .libcap-ng-guest.config <<'KCONFIG'
          CONFIG_EXPERT=y
          CONFIG_EMBEDDED=y
          CONFIG_PRINTK=y
          CONFIG_BUG=y
          CONFIG_MULTIUSER=y
          CONFIG_BINFMT_ELF=y
          CONFIG_BLK_DEV_INITRD=y
          CONFIG_RD_GZIP=y
          CONFIG_DEVTMPFS=y
          CONFIG_DEVTMPFS_MOUNT=y
          CONFIG_PROC_FS=y
          CONFIG_SYSFS=y
          CONFIG_SHMEM=y
          CONFIG_TMPFS=y
          CONFIG_FUTEX=y
          CONFIG_POSIX_TIMERS=y
          CONFIG_AIO=y
          CONFIG_ADVISE_SYSCALLS=y
          CONFIG_MEMFD_CREATE=y
          CONFIG_RSEQ=y
          CONFIG_TTY=y
          CONFIG_SERIAL_EARLYCON=y
          CONFIG_SERIAL_AMBA_PL011=y
          CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
          CONFIG_SMP=n
          CONFIG_COMPAT=n
          CONFIG_MODULES=n
          CONFIG_NET=n
          CONFIG_BLOCK=n
          CONFIG_DEBUG_INFO_NONE=y
          CONFIG_PRINTK_TIME=n
          KCONFIG
          scripts/kconfig/merge_config.sh -m .config .libcap-ng-guest.config
          make ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ olddefconfig

          for requirement in \
            CONFIG_MULTIUSER=y \
            CONFIG_BINFMT_ELF=y \
            CONFIG_BLK_DEV_INITRD=y \
            CONFIG_RD_GZIP=y \
            CONFIG_DEVTMPFS=y \
            CONFIG_PROC_FS=y \
            CONFIG_SYSFS=y \
            CONFIG_SHMEM=y \
            CONFIG_TMPFS=y \
            CONFIG_SERIAL_AMBA_PL011_CONSOLE=y; do
            grep -Fxq "$requirement" .config || {
              echo "libcap-ng guest kernel omitted $requirement" >&2
              exit 1
            }
          done
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ Image
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/boot"
          cp arch/arm64/boot/Image "$out/boot/Image"
          cp .config "$out/boot/config"
        '';
      }
    ];
  };

  guestInit = targetPackages.mkDerivation {
    pname = "libcap-ng-aarch64-guest-init";
    version = "0";
    src = null;
    runtimeDeps = [targetPackages.bash];
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
          #include <sys/wait.h>
          #include <unistd.h>

          static void mount_required(const char *source, const char *target,
                                     const char *type) {
            if (mount(source, target, type, 0, NULL) != 0 && errno != EBUSY) {
              perror(target);
              exit(EXIT_FAILURE);
            }
          }

          int main(void) {
            int child_succeeded = 0;
            int status = 0;
            pid_t child;

            mount_required("proc", "/proc", "proc");
            mount_required("sysfs", "/sys", "sysfs");
            mount_required("devtmpfs", "/dev", "devtmpfs");

            child = fork();
            if (child < 0) {
              perror("fork");
            } else if (child == 0) {
              execl("${targetPackages.bash}/bin/bash", "bash", "/run-tests",
                    (char *)NULL);
              perror("bash");
              _exit(EXIT_FAILURE);
            } else if (waitpid(child, &status, 0) < 0) {
              perror("waitpid");
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
              child_succeeded = 1;
            }

            if (child_succeeded) {
              puts("LIBCAP_GUEST_RESULT:PASS");
            } else {
              puts("LIBCAP_GUEST_RESULT:FAIL");
            }
            fflush(NULL);
            sync();
            reboot(RB_POWER_OFF);
            pause();
            return EXIT_FAILURE;
          }
          C
          "$CC" -std=c11 -Wall -Wextra -Werror guest-init.c -o guest-init
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp guest-init "$out/bin/guest-init"
        '';
      }
    ];
  };

  runAs = targetPackages.mkDerivation {
    pname = "libcap-ng-aarch64-run-as";
    version = "0";
    src = null;

    phases = [
      {
        name = "build";
        script = ''
          cat > run-as.c <<'C'
          #define _DEFAULT_SOURCE

          #include <errno.h>
          #include <grp.h>
          #include <stdio.h>
          #include <stdlib.h>
          #include <sys/types.h>
          #include <unistd.h>

          static unsigned long parse_id(const char *text) {
            char *end = NULL;
            unsigned long value;

            errno = 0;
            value = strtoul(text, &end, 10);
            if (errno != 0 || end == text || *end != '\0') {
              fprintf(stderr, "invalid identity: %s\n", text);
              exit(64);
            }
            return value;
          }

          int main(int argc, char **argv) {
            unsigned long parsed_gid;
            unsigned long parsed_uid;
            uid_t uid;
            gid_t gid;

            if (argc < 4) {
              fputs("usage: run-as UID GID PROGRAM [ARG...]\n", stderr);
              return 64;
            }
            parsed_uid = parse_id(argv[1]);
            parsed_gid = parse_id(argv[2]);
            uid = (uid_t)parsed_uid;
            gid = (gid_t)parsed_gid;
            if ((unsigned long)uid != parsed_uid || (unsigned long)gid != parsed_gid) {
              fputs("identity is out of range\n", stderr);
              return 64;
            }
            if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
              perror("drop identity");
              return 1;
            }
            execvp(argv[3], &argv[3]);
            perror(argv[3]);
            return 127;
          }
          C
          "$CC" -std=c11 -Wall -Wextra -Werror run-as.c -o run-as
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp run-as "$out/bin/run-as"
        '';
      }
    ];
  };

  kernelCapabilityProbe = targetPackages.mkDerivation {
    pname = "libcap-ng-aarch64-kernel-capability-probe";
    version = "0";
    src = null;
    runtimeDeps = [payload];

    phases = [
      {
        name = "build";
        script = ''
          cat > capability-probe.c <<'C'
          #define _GNU_SOURCE

          #include <cap-ng.h>
          #include <errno.h>
          #include <linux/capability.h>
          #include <stdio.h>
          #include <string.h>
          #include <sys/prctl.h>
          #include <sys/syscall.h>
          #include <unistd.h>

          extern int capget(cap_user_header_t header,
                            const cap_user_data_t data);

          static int print_proc_capabilities(const char *path) {
            char line[256];
            FILE *status = fopen(path, "re");

            if (status == NULL) {
              perror(path);
              return 1;
            }

            printf("status-path=%s\n", path);
            while (fgets(line, sizeof(line), status) != NULL) {
              if (strncmp(line, "Cap", 3) == 0) {
                fputs(line, stdout);
              }
            }

            if (ferror(status)) {
              perror(path);
              fclose(status);
              return 1;
            }
            fclose(status);
            return 0;
          }

          int main(void) {
            struct __user_cap_header_struct header = {0};
            struct __user_cap_data_struct data[2] = {0};
            char thread_status[64];
            long tid = syscall(SYS_gettid);
            int failed = 0;
            int saved_errno;
            int result;

            printf("pid=%ld tid=%ld\n", (long)getpid(), tid);

            errno = 0;
            result = syscall(SYS_capget, &header, NULL);
            saved_errno = errno;
            printf("capget-negotiate result=%d errno=%d version=0x%08x\n",
                   result, saved_errno, header.version);
            if (result != 0 || saved_errno != 0 ||
                header.version != _LINUX_CAPABILITY_VERSION_3) {
              failed = 1;
            }

            header.pid = (int)tid;
            errno = 0;
            result = syscall(SYS_capget, &header, data);
            saved_errno = errno;
            printf("capget-current result=%d errno=%d\n", result, saved_errno);
            if (result != 0) {
              failed = 1;
            }

            memset(&header, 0, sizeof(header));
            memset(data, 0, sizeof(data));
            errno = 0;
            result = capget(&header, NULL);
            saved_errno = errno;
            printf("libc-capget-negotiate result=%d errno=%d version=0x%08x\n",
                   result, saved_errno, header.version);
            if (result != 0 || saved_errno != 0 ||
                header.version != _LINUX_CAPABILITY_VERSION_3) {
              failed = 1;
            }

            header.pid = (int)tid;
            errno = 0;
            result = capget(&header, data);
            saved_errno = errno;
            printf("libc-capget-current result=%d errno=%d\n",
                   result, saved_errno);
            if (result != 0) {
              failed = 1;
            }

            errno = 0;
            result = prctl(PR_CAPBSET_READ, CAP_CHOWN, 0, 0, 0);
            saved_errno = errno;
            printf("prctl-bounding result=%d errno=%d\n", result, saved_errno);
            if (result < 0) {
              failed = 1;
            }

            errno = 0;
            result = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                           CAP_CHOWN, 0, 0);
            saved_errno = errno;
            printf("prctl-ambient result=%d errno=%d\n", result, saved_errno);
            if (result < 0) {
              failed = 1;
            }

            if (print_proc_capabilities("/proc/self/status") != 0) {
              failed = 1;
            }
            if (snprintf(thread_status, sizeof(thread_status),
                         "/proc/%ld/status", tid) < 0 ||
                print_proc_capabilities(thread_status) != 0) {
              failed = 1;
            }

            errno = 0;
            result = capng_get_caps_process();
            saved_errno = errno;
            printf("libcap-ng-get-process result=%d errno=%d\n",
                   result, saved_errno);
            if (result != 0) {
              failed = 1;
            }
            return failed;
          }
          C
          "$CC" -std=c11 -Wall -Wextra -Werror \
            -I${payload}/include \
            capability-probe.c \
            -L${payload}/lib -Wl,-rpath,${payload}/lib -lcap-ng \
            -o capability-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp capability-probe "$out/bin/capability-probe"
        '';
      }
    ];
  };

  closureDeps = [
    targetPackages.bash
    targetPackages.coreutils
    targetPackages.python3
    guestInit
    kernelCapabilityProbe
    runAs
    payload
  ];
  closureGraph =
    lib.concatLists
    (lib.imap (index: dependency: [
        "guest-closure-${builtins.toString index}"
        dependency
      ])
      closureDeps);

  initramfs = buildPackages.mkDerivation {
    pname = "libcap-ng-aarch64-guest-initramfs";
    version = "0";
    src = null;
    buildDeps = [
      buildPackages.coreutils
      buildPackages.cpio
      buildPackages.findutils
      buildPackages.pigz
    ];
    exportReferencesGraph = closureGraph;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          grep -h '^/nix/store/' guest-closure-* | sort -u > closure-paths

          mkdir -p root/bin root/dev root/etc root/nix/store root/proc root/sys root/tmp
          while IFS= read -r path; do
            cp -a "$path" root"$path"
          done < closure-paths

          chmod 1777 root/tmp
          ln -sfn ${targetPackages.bash}/bin/bash root/bin/sh
          cp ${guestInit}/bin/guest-init root/init
          cat > root/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/sh
          nobody:x:65534:65534:nobody:/tmp:/bin/sh
          PASSWD
          cat > root/etc/group <<'GROUP'
          root:x:0:
          nogroup:x:65534:
          GROUP

          cat > root/run-tests <<'TESTS'
          set -eu
          export PATH="${targetPackages.coreutils}/bin:${targetPackages.bash}/bin"
          export PYTHONHASHSEED=0

          test_root=${payload}/libexec/libcap-ng-tests
          run_as=${runAs}/bin/run-as

          echo LIBCAP_KERNEL_PROBE_BEGIN
          "$run_as" 65534 65534 \
            ${kernelCapabilityProbe}/bin/capability-probe
          echo LIBCAP_KERNEL_PROBE_PASS

          run_one() {
            identity=$1
            relative=$2
            executable="$test_root/$relative"
            work_directory="/tmp/''${relative//\//-}-$identity"
            mkdir -p "$work_directory"
            chmod 1777 "$work_directory"

            echo "LIBCAP_TEST_BEGIN:$relative:$identity"
            set +e
            if [ "$identity" = root ]; then
              (cd "$work_directory" && "$executable")
            else
              (cd "$work_directory" && "$run_as" 65534 65534 "$executable")
            fi
            status=$?
            set -e

            case "$status" in
              0) echo "LIBCAP_TEST_PASS:$relative:$identity" ;;
              77)
                echo "LIBCAP_TEST_FAIL:$relative:$identity:unsupported-skip"
                return 77
                ;;
              *)
                echo "LIBCAP_TEST_FAIL:$relative:$identity:$status"
                return "$status"
                ;;
            esac
          }

          while IFS= read -r relative; do
            case "$relative" in
              src/thread_test)
                run_one root "$relative"
                ;;
              src/lib_test | src/change_id_test)
                run_one unprivileged "$relative"
                run_one root "$relative"
                ;;
              *)
                run_one unprivileged "$relative"
                ;;
            esac
          done < "$test_root/manifest"

          set -- ${payload}/lib/python*/site-packages
          [ "$#" -eq 1 ] && [ -d "$1" ]
          python_path=$1
          python=${targetPackages.python3}/bin/python3

          echo LIBCAP_TEST_BEGIN:python/import:unprivileged
          "$run_as" 65534 65534 env PYTHONPATH="$python_path" \
            "$python" -c 'import capng'
          echo LIBCAP_TEST_PASS:python/import:unprivileged

          echo LIBCAP_TEST_BEGIN:python/capng-test.py:unprivileged
          "$run_as" 65534 65534 env PYTHONPATH="$python_path" \
            "$python" "$test_root/python/capng-test.py"
          echo LIBCAP_TEST_PASS:python/capng-test.py:unprivileged
          TESTS
          chmod 0755 root/init root/run-tests

          mkdir -p "$out"
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
  buildPackages.mkDerivation {
    pname = "libcap-ng-aarch64-guest-qualification";
    inherit version;
    src = null;
    requiredSystemFeatures = ["kvm"];
    buildDeps = [
      buildPackages.coreutils
      buildPackages.grep
      buildPackages.qemu
      buildPackages.sed
    ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu
          serial="$TMPDIR/serial.log"
          set +e
          # The Python-inclusive initramfs expands past 500 MiB. Keep it
          # below rootfs' default half-RAM tmpfs limit, including metadata.
          timeout 300 ${buildPackages.qemu}/bin/qemu-system-aarch64 \
            -nodefaults \
            -no-user-config \
            -display none \
            -monitor none \
            -machine virt,gic-version=2 \
            -cpu cortex-a57 \
            -accel tcg \
            -m 2048 \
            -smp 1 \
            -kernel ${kernel}/boot/Image \
            -initrd ${initramfs}/initrd.img \
            -append 'console=ttyAMA0 rdinit=/init panic=-1' \
            -serial stdio \
            -no-reboot \
            > "$serial" 2>&1
          qemu_status=$?
          set -e
          sed -i 's/\r$//' "$serial"
          cat "$serial"

          if [ "$qemu_status" -eq 124 ]; then
            echo "libcap-ng AArch64 guest timed out" >&2
            exit 1
          fi
          test "$qemu_status" -eq 0
          test "$(grep -Fxc 'LIBCAP_GUEST_RESULT:PASS' "$serial")" -eq 1
          ! grep -Fq 'LIBCAP_GUEST_RESULT:FAIL' "$serial"
          ! grep -Fq 'LIBCAP_TEST_FAIL:' "$serial"

          require_outcome() {
            relative=$1
            identity=$2
            grep -Fxq "LIBCAP_TEST_PASS:$relative:$identity" "$serial"
          }

          while IFS= read -r relative; do
            case "$relative" in
              src/thread_test)
                require_outcome "$relative" root
                ;;
              src/lib_test | src/change_id_test)
                require_outcome "$relative" unprivileged
                require_outcome "$relative" root
                ;;
              *)
                require_outcome "$relative" unprivileged
                ;;
            esac
          done < ${payload}/libexec/libcap-ng-tests/manifest
          require_outcome python/import unprivileged
          require_outcome python/capng-test.py unprivileged

          mkdir -p "$out"
          cp "$serial" "$out/serial.log"
          {
            echo PASS
            echo architecture=aarch64-linux
            echo backend=qemu-system-aarch64
            echo accelerator=tcg
            echo payload=${payload}
            echo configured_tests=$(wc -l < ${payload}/libexec/libcap-ng-tests/manifest)
            echo root_and_unprivileged_process_capability_tests=true
            echo python_bindings_tested=true
          } > "$out/result"
        '';
      }
    ];
  }
