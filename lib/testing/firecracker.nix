# lib/testing/firecracker.nix — Firecracker-based headless microVM test harness
#
# Architecture:
#   1. Build a minimal rootfs ext4 image with Nix store closures
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot Firecracker with --no-api --config-file (no REST API)
#   3. The test script IS the init process (PID 1) — no systemd, no agent
#   4. Serial console (Firecracker stdout) captures test output
#   5. Init prints TEST_RESULT:PASS or TEST_RESULT:FAIL to /dev/ttyS0
#   6. Init triggers SysRq reboot (echo b > /proc/sysrq-trigger) for clean FC exit
#
# Requirements:
#   - Kernel with built-in: VIRTIO_MMIO, VIRTIO_BLK, EXT4_FS, SERIAL_8250,
#     DEVTMPFS, DEVTMPFS_MOUNT, TMPFS, PROC_FS, SYSFS
#   - Uncompressed vmlinux ELF kernel image (not bzImage/vmlinuz)
#   - requiredSystemFeatures = [ "kvm" ] on the builder
#   - Firecracker binary (pkgs.firecracker)
{
  pkgs,
  lib,
}: let
  bootstrapTools = pkgs.bootstrapTools;
  bashPkg = pkgs.bash;
  coreutilsPkg = pkgs.coreutils;
  utilLinuxPkg = pkgs.util-linux;
  kernel = pkgs.linux;

  # -------------------------------------------------------------------------
  # Build a minimal rootfs ext4 image for headless Firecracker tests
  # -------------------------------------------------------------------------
  # Uses exportReferencesGraph to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  mkFirecrackerRootfs = {
    pname,
    testScript,
    rootfsDeps,
  }: let
    # Callers describe their runtime needs without having to know which
    # packages the harness itself supplies.  Deduplicate at that boundary so
    # an explicit dependency that is also a harness dependency does not create
    # duplicate reference-graph roots.
    allDeps = lib.unique (
      rootfsDeps
      ++ [
        bashPkg
        coreutilsPkg
        utilLinuxPkg
        bootstrapTools
      ]
    );

    # Build the exportReferencesGraph pairs list: ["name1" drv1 "name2" drv2 ...]
    graphPairs =
      lib.imap (i: dep: [
        "closure-${builtins.toString i}"
        dep
      ])
      allDeps;
    flatGraphPairs = builtins.concatLists graphPairs;

    regInfo = import ../build/closure-info.nix {inherit pkgs lib;} {
      rootPaths = allDeps;
      pname = "fc-rootfs-${pname}-closure-info";
    };

    closureFileNames = builtins.genList (i: "closure-${builtins.toString i}") (builtins.length allDeps);

    catClosures = builtins.concatStringsSep " " closureFileNames;

    # Build PATH entries for all deps — include both bin/ and sbin/
    depPaths = builtins.concatStringsSep ":" (
      builtins.concatMap (
        dep: let
          base = builtins.toString dep;
        in [
          "${base}/bin"
          "${base}/sbin"
        ]
      )
      allDeps
    );

    # Bootstrap toolchain paths for compilation inside the VM
    btBase = builtins.toString bootstrapTools;
    dynamicLinker = "${btBase}/lib/${lib.platform.dynamicLinker}";

    initScript = ''
      #!/bin/sh
      # /init — PID 1 for headless Firecracker microVM test
      # Mounts essential filesystems, runs the test, reports result via serial.

      # PATH must be set BEFORE mount calls — kernel runs init with empty env.
      # /usr/local/bin here is inside the generated Firecracker rootfs, not the
      # host filesystem. It contains gcc/g++ wrappers that must shadow raw
      # bootstrap tools.
      export PATH="/usr/local/bin:${depPaths}:/bin:/usr/bin:/sbin:/usr/sbin"
      export HOME=/tmp

      # Bootstrap gcc needs explicit include/library paths (no ccWrapper in VM)
      export C_INCLUDE_PATH="${btBase}/include-glibc"
      export LIBRARY_PATH="${btBase}/lib"
      export LD_LIBRARY_PATH="${btBase}/lib"

      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      mount -t devtmpfs devtmpfs /dev
      mount -t tmpfs tmpfs /tmp
      mount -t tmpfs tmpfs /run

      # Run the test in a child shell, then capture its exit code. Placing a
      # shell compound command directly on the left side of `||` suppresses
      # errexit throughout that compound command, so failed assertions could
      # otherwise fall through to TEST_RESULT:PASS.
      cat > /run/aos-vm-test << 'AOS_VM_TEST_EOF'
      set -e
      ${testScript}
      AOS_VM_TEST_EOF
      chmod 0700 /run/aos-vm-test

      test_result=0
      ${bashPkg}/bin/bash /run/aos-vm-test || test_result=$?

      if [ "$test_result" -eq 0 ]; then
        echo 'TEST_RESULT:PASS'
      else
        echo 'TEST_RESULT:FAIL'
      fi

      # Shut down via reboot(2) instead of SysRq 'b'. The previous
      # `echo b > /proc/sysrq-trigger` is `emergency_restart()` — an
      # immediate hard reset that skips every device .shutdown callback,
      # including the 8250 UART's tx-FIFO drain. The trailing
      # TEST_RESULT:PASS|FAIL line lives in that FIFO between the guest
      # kernel and Firecracker's emulated UART; under heavy host CPU
      # contention Firecracker's vmm thread may not be scheduled in the
      # 200 ms grace before the reset, so the marker is lost and the
      # host's post-mortem `grep TEST_RESULT:` lands in the "No test
      # result marker found" branch — a flake that scales with host load.
      #
      # `reboot -f` (util-linux is in allDeps and already symlinked into
      # /sbin) issues reboot(2) with LINUX_REBOOT_CMD_RESTART. The
      # kernel runs the orderly restart path which drains tty/UART
      # buffers as part of device_shutdown(); Firecracker still exits
      # cleanly on the resulting KVM_EXIT_SYSTEM_EVENT. The pre-sync
      # belts-and-braces filesystem buffers (not strictly needed for
      # the marker, but free); the half-second sleep gives Firecracker
      # extra slack on top of what reboot(2) provides.
      sync
      sleep 0.5
      reboot -f
    '';
  in
    pkgs.mkDerivation {
      pname = "fc-rootfs-${pname}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.e2fsprogs
        pkgs.coreutils
        pkgs.fakeroot
      ];

      exportReferencesGraph = flatGraphPairs;

      AOS_BASH = builtins.toString bashPkg;
      COREUTILS = builtins.toString coreutilsPkg;
      UTIL_LINUX = builtins.toString utilLinuxPkg;
      BOOTSTRAP = builtins.toString bootstrapTools;
      DYNAMIC_LINKER = dynamicLinker;
      REGINFO = builtins.toString regInfo;

      phases = [
        {
          name = "build-rootfs";
          script = ''
                        mkdir -p rootfs/nix/store
                        # Preserve the real store's trusted-parent mode. The
                        # ownership is normalized under fakeroot when mkfs
                        # records the staging tree in the guest image.
                        chmod 0755 rootfs/nix rootfs/nix/store
                        # FHS-looking paths in this builder are staged under
                        # ./rootfs and become the guest VM filesystem only.
                        mkdir -p rootfs/bin rootfs/sbin rootfs/usr/bin rootfs/usr/sbin rootfs/usr/local/bin
                        mkdir -p rootfs/dev rootfs/proc rootfs/sys rootfs/tmp rootfs/run
                        mkdir -p rootfs/etc rootfs/var/log rootfs/var/tmp

                        # Collect all unique store paths from the closure graphs
                        cat ${catClosures} \
                          | grep '^/nix/store/' | sort -u > all-paths

                        echo "==> Copying $(wc -l < all-paths) store paths to rootfs"

                        count=0
                        total=$(wc -l < all-paths)
                        while IFS= read -r p; do
                          count=$((count + 1))
                          if [ -e "$p" ]; then
                            cp -a "$p" rootfs/nix/store/
                          fi
                          if [ $((count % 10)) -eq 0 ]; then
                            printf '\r    [%d/%d]' "$count" "$total"
                          fi
                        done < all-paths
                        echo ""

                        # Headless tests do not run the stage-2 Nix DB seed
                        # unit, but they can load the same registration stream
                        # explicitly when they exercise Nix store operations.
                        cp "$REGINFO/registration" rootfs/aos-registration

                        # /bin/sh -> bash (required for shell scripts)
                        ln -sfn $AOS_BASH/bin/bash rootfs/bin/sh
                        ln -sfn $AOS_BASH/bin/bash rootfs/bin/bash

                        # coreutils in /bin and /usr/bin
                        for bin in $COREUTILS/bin/*; do
                          name=$(basename "$bin")
                          ln -sfn "$bin" "rootfs/bin/$name" 2>/dev/null || true
                          ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                        done

                        # util-linux (mount, umount, etc.) in /bin, /sbin, /usr/bin, /usr/sbin
                        if [ -d "$UTIL_LINUX/bin" ]; then
                          for bin in $UTIL_LINUX/bin/*; do
                            name=$(basename "$bin")
                            if [ ! -e "rootfs/bin/$name" ]; then
                              ln -sfn "$bin" "rootfs/bin/$name" 2>/dev/null || true
                            fi
                            if [ ! -e "rootfs/usr/bin/$name" ]; then
                              ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                            fi
                          done
                        fi
                        if [ -d "$UTIL_LINUX/sbin" ]; then
                          for bin in $UTIL_LINUX/sbin/*; do
                            name=$(basename "$bin")
                            ln -sfn "$bin" "rootfs/sbin/$name" 2>/dev/null || true
                            if [ ! -e "rootfs/usr/sbin/$name" ]; then
                              ln -sfn "$bin" "rootfs/usr/sbin/$name" 2>/dev/null || true
                            fi
                          done
                        fi

                        # bootstrap tools in /usr/bin (skip compiler/linker — wrappers created below)
                        for bin in $BOOTSTRAP/bin/*; do
                          name=$(basename "$bin")
                          case "$name" in
                            gcc|g++|cc|c++|ld|cpp) continue ;;
                          esac
                          if [ ! -e "rootfs/usr/bin/$name" ]; then
                            ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                          fi
                        done

                        # Create gcc/g++/ld/cpp wrapper scripts in the VM-local
                        # /usr/local/bin. These do not reference the host rootfs.
                        # (must shadow raw bootstrap gcc in PATH — see init PATH ordering)
                        # Raw bootstrap gcc doesn't know about our glibc or dynamic linker paths

                        # Discover C++ include paths (same logic as pkgs/default.nix ccWrapper)
                        # Guard: only probe if include/c++ exists (cc-wrapper may not have it)
                        BT_ROOT=$(dirname $BOOTSTRAP/lib)
                        BT_CXX=""
                        BT_CXX_ARCH=""
                        BT_CXX_BACKWARD=""
                        BT_GCC_LIB=""
                        if [ -d "$BT_ROOT/include/c++" ]; then
                          CXX_VER=$(ls "$BT_ROOT/include/c++")
                          BT_CXX="$BT_ROOT/include/c++/$CXX_VER"
                          BT_CXX_ARCH=$(ls -d "$BT_CXX"/*-linux-gnu 2>/dev/null | head -1 || true)
                          BT_CXX_BACKWARD="$BT_CXX/backward"
                        fi
                        if [ -d "$BOOTSTRAP/lib/gcc" ]; then
                          BT_GCC_LIB=$(ls -d "$BOOTSTRAP/lib/gcc"/*/*/ 2>/dev/null | head -1 || true)
                        fi

                        cat > rootfs/usr/local/bin/gcc << GCCWRAP
            #!/bin/sh
            exec $BOOTSTRAP/bin/gcc -B$BOOTSTRAP/lib -isystem $BOOTSTRAP/include-glibc -L$BOOTSTRAP/lib -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYNAMIC_LINKER -Wl,-rpath,$BOOTSTRAP/lib -Wl,-rpath,$BT_GCC_LIB "\$@"
            GCCWRAP
                        cp rootfs/usr/local/bin/gcc rootfs/usr/local/bin/cc

                        # g++ uses -nostdinc++ then re-adds C++ headers before glibc
                        # (fixes #include_next from cstdlib finding stdlib.h)
                        cat > rootfs/usr/local/bin/g++ << GPPWRAP
            #!/bin/sh
            exec $BOOTSTRAP/bin/g++ -nostdinc++ -isystem $BT_CXX -isystem $BT_CXX_ARCH -isystem $BT_CXX_BACKWARD -isystem $BOOTSTRAP/include-glibc -B$BOOTSTRAP/lib -L$BOOTSTRAP/lib -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYNAMIC_LINKER -Wl,-rpath,$BOOTSTRAP/lib -Wl,-rpath,$BT_GCC_LIB "\$@"
            GPPWRAP
                        cp rootfs/usr/local/bin/g++ rootfs/usr/local/bin/c++

                        cat > rootfs/usr/local/bin/cpp << CPPWRAP
            #!/bin/sh
            exec $BOOTSTRAP/bin/cpp -isystem $BOOTSTRAP/include-glibc "\$@"
            CPPWRAP

                        cat > rootfs/usr/local/bin/ld << LDWRAP
            #!/bin/sh
            exec $BOOTSTRAP/bin/ld -L$BOOTSTRAP/lib -L$BT_GCC_LIB -dynamic-linker=$DYNAMIC_LINKER -rpath $BOOTSTRAP/lib -rpath $BT_GCC_LIB "\$@"
            LDWRAP
                        chmod +x rootfs/usr/local/bin/gcc rootfs/usr/local/bin/cc rootfs/usr/local/bin/g++ rootfs/usr/local/bin/c++ rootfs/usr/local/bin/cpp rootfs/usr/local/bin/ld

                        # util-linux is built without reboot(8), but the
                        # headless init needs an orderly reboot syscall so
                        # serial TEST_RESULT markers drain before Firecracker
                        # exits. Build the tiny helper into the VM rootfs.
                        cat > reboot.c << 'REBOOT_C'
            #include <stdio.h>
            #include <sys/reboot.h>
            #include <unistd.h>

            int main(void) {
              sync();
              if (reboot(RB_AUTOBOOT) != 0) {
                perror("reboot");
                return 1;
              }
              return 0;
            }
            REBOOT_C
                        cc reboot.c -o rootfs/sbin/reboot

                        # Symlink binaries from all rootfsDeps
                        ${builtins.concatStringsSep "\n" (
              builtins.map (dep: ''
                if [ -d "${builtins.toString dep}/bin" ]; then
                  for bin in "${builtins.toString dep}/bin/"*; do
                    name=$(basename "$bin")
                    if [ ! -e "rootfs/usr/bin/$name" ]; then
                      ln -sfn "$bin" "rootfs/usr/bin/$name" 2>/dev/null || true
                    fi
                  done
                fi
                if [ -d "${builtins.toString dep}/sbin" ]; then
                  for bin in "${builtins.toString dep}/sbin/"*; do
                    name=$(basename "$bin")
                    if [ ! -e "rootfs/usr/sbin/$name" ]; then
                      ln -sfn "$bin" "rootfs/usr/sbin/$name" 2>/dev/null || true
                    fi
                  done
                fi
              '')
              rootfsDeps
            )}

                        # Minimal /etc files
                        echo "aos-fc-test" > rootfs/etc/hostname
                        cat > rootfs/etc/passwd << 'PASSWD'
            root:x:0:0:root:/root:/bin/sh
            nobody:x:65534:65534:Nobody:/:/sbin/nologin
            PASSWD
                        cat > rootfs/etc/group << 'GROUP'
            root:x:0:
            nobody:x:65534:
            GROUP

                        # Write the init script
                        cat > rootfs/init << 'INITEOF'
            ${initScript}
            INITEOF
                        chmod +x rootfs/init

                        # Calculate image size: use actual store closure size (not rootfs
                        # symlink tree), then add generous overhead for ext4 metadata.
                        STORE_KB=0
                        while IFS= read -r p; do
                          if [ -e "$p" ]; then
                            THIS_KB=$(du -sk "$p" 2>/dev/null | cut -f1)
                            STORE_KB=$((STORE_KB + THIS_KB))
                          fi
                        done < all-paths
                        STORE_MB=$(( STORE_KB / 1024 ))
                        # 3x for ext4 overhead (journal, inodes, superblocks) + 512MB headroom
                        IMAGE_MB=$(( STORE_MB * 3 + 512 ))
                        # Minimum 512MB to avoid tiny filesystem issues
                        if [ "$IMAGE_MB" -lt 512 ]; then IMAGE_MB=512; fi

                        echo "==> Rootfs closure: ''${STORE_MB}MB, image: ''${IMAGE_MB}MB"
                        # stdenv setup.sh creates $out as a directory; remove it so
                        # mkfs.ext4 can write a flat image file there.
                        rm -rf "$out"
                        # Nix builders do not run as uid 0, but the populated
                        # guest root filesystem must. In particular, native
                        # services reject secrets beneath store parents owned
                        # by an unrelated build uid. fakeroot makes mkfs record
                        # production-like uid/gid values without a host mount.
                        fakeroot -- mkfs.ext4 -d rootfs -L rootfs -m 1 -q \
                          "$out" "''${IMAGE_MB}M"
          '';
        }
      ];
    };
in {
  inherit mkFirecrackerRootfs;
}
