# lib/testing/firecracker.nix — Firecracker-based headless microVM test harness
#
# Architecture:
#   1. Build a minimal rootfs ext4 image with Nix store closures
#      (uses mkfs.ext4 -d — no losetup/mount, sandbox-compatible)
#   2. Boot Firecracker with --no-api --config-file (no REST API)
#   3. Init runs assertions from a separate read-only virtio input disk
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
  imageMetadata = import ../build/image-metadata.nix {inherit pkgs;};

  # Compile outside runtime image assembly: the compiler wrapper embeds $out/lib
  # in RPATHs, so a runtime scratch output would make the base irreproducible.
  rebootHelper = pkgs.mkDerivation {
    pname = "fc-reboot-helper";
    version = "0";
    src = null;
    phases = [
      {
        name = "build";
        script = ''
          cat > reboot.c <<'SOURCE'
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
          SOURCE
          mkdir -p "$out/bin"
          cc reboot.c -o "$out/bin/reboot"
        '';
      }
    ];
  };

  # -------------------------------------------------------------------------
  # Build a minimal rootfs ext4 image for headless Firecracker tests
  # -------------------------------------------------------------------------
  # Uses closure-info to discover the Nix store closure, then
  # creates an ext4 image populated via mkfs.ext4 -d (no mount needed).

  mkFirecrackerRootfs = {
    development ? false,
    rootfsDeps,
    extraWritableMiB ? 0,
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
        pkgs.grep
        utilLinuxPkg
        bootstrapTools
        rebootHelper
      ]
    );

    regInfo = import ../build/closure-info.nix {inherit pkgs lib;} {
      rootPaths = allDeps;
      pname = "fc-rootfs-closure-info";
    };

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

    # Split libc paths for compilation inside the VM
    libc = pkgs.glibc;
    libcDev = libc.dev or libc;

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

      # The VM compiler uses the same split libc outputs as the build stdenv.
      export C_INCLUDE_PATH="${libcDev}/include"
      export LIBRARY_PATH="${libc}/lib"
      export LD_LIBRARY_PATH="${libc}/lib"

      mount -t proc proc /proc
      mount -t sysfs sysfs /sys
      mount -t devtmpfs devtmpfs /dev
      mount -t tmpfs tmpfs /tmp
      mount -t tmpfs tmpfs /run

      # Run the test in a child shell, then capture its exit code. Placing a
      # shell compound command directly on the left side of `||` suppresses
      # errexit throughout that compound command, so failed assertions could
      # otherwise fall through to TEST_RESULT:PASS.
      mkdir -p /run/aos-test-input
      mount -t ext4 -o ro /dev/vdb /run/aos-test-input || {
        echo 'TEST_RESULT:FAIL'
        sync
        reboot -f
      }
      cp /run/aos-test-input/test /run/aos-vm-test
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

    # Keep the stable boot harness separate from the per-test input volume.
    initScriptFile = pkgs.writeTextFile {
      name = "fc-init";
      text = initScript;
      destination = "/init";
      executable = true;
    };
  in
    (
      if (pkgs.sharedImageCacheDir or null) == null || !development
      then pkgs.mkDerivation
      else (import ./image-recipe.nix {inherit pkgs lib;}) {}
    ) {
      pname = "fc-rootfs-base";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.e2fsprogs
        pkgs.coreutils
        pkgs.fakeroot
        pkgs.python3
      ];

      AOS_BASH = builtins.toString bashPkg;
      COREUTILS = builtins.toString coreutilsPkg;
      UTIL_LINUX = builtins.toString utilLinuxPkg;
      BOOTSTRAP = builtins.toString bootstrapTools;
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
                        cp "$REGINFO/store-paths" all-paths

                        echo "==> Copying $(wc -l < all-paths) store paths to rootfs"

                        count=0
                        total=$(wc -l < all-paths)
                        while IFS= read -r p; do
                          count=$((count + 1))
                          if [ -e "$p" ]; then
                            # NAR inputs have no hardlink identity; store
                            # optimization must not change guest inode layout.
                            cp -a --no-preserve=links "$p" rootfs/nix/store/
                          fi
                          if [ $((count % 10)) -eq 0 ]; then
                            printf '\r    [%d/%d]' "$count" "$total"
                          fi
                        done < all-paths
                        echo ""

                        # Headless tests do not run the stage-2 Nix DB seed
                        # unit, but they can load the same registration stream
                        # explicitly when they exercise Nix store operations.
                        mkdir -p rootfs/usr/lib/aos
                        cp "$REGINFO/registration" rootfs/usr/lib/aos/nix-registration

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

                        # Reuse the source-built stdenv wrappers. bootstrapTools
                        # is a compiler wrapper, not a combined GCC/glibc tree;
                        # its embedded flags select the proper split outputs.
                        for compiler in gcc cc g++ c++ ld; do
                          ln -s "$BOOTSTRAP/bin/$compiler" "rootfs/usr/local/bin/$compiler"
                        done
                        cat > rootfs/usr/local/bin/cpp << CPPWRAP
            #!/bin/sh
            exec $BOOTSTRAP/bin/gcc -E "\$@"
            CPPWRAP
                        chmod +x rootfs/usr/local/bin/cpp

                        # Orderly reboot drains serial result markers.
                        cp ${rebootHelper}/bin/reboot rootfs/sbin/reboot

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

                        # Install the generated init script. It is materialized
                        # separately so large lifecycle tests never become one
                        # oversized argument to this derivation's builder.
                        cp ${initScriptFile}/init rootfs/init

                        # Host allocation and directory st_size must not change
                        # image geometry when the same tree is reconstructed.
                        TREE_BYTES=$(${imageMetadata.command} size rootfs)
                        STORE_MB=$(( TREE_BYTES / 1048576 ))
                        # 3x for ext4 overhead (journal, inodes, superblocks) + 512MB headroom.
                        # Some tests also keep full guest checkpoints on this writable root.
                        IMAGE_MB=$(( STORE_MB * 3 + 512 + ${toString extraWritableMiB} ))
                        # Minimum 512MB to avoid tiny filesystem issues
                        if [ "$IMAGE_MB" -lt 512 ]; then IMAGE_MB=512; fi

                        echo "==> Rootfs closure: ''${STORE_MB}MB, image: ''${IMAGE_MB}MB"
                        # Keep the directory output compatible with runtime recipes.
                        mkdir -p "$out"
                        # Nix builders do not run as uid 0, but the populated
                        # guest root filesystem must. In particular, native
                        # services reject secrets beneath store parents owned
                        # by an unrelated build uid. fakeroot makes mkfs record
                        # production-like uid/gid values without a host mount.
                        ${imageMetadata.environment}
                        IMAGE_UUID=$(${imageMetadata.command} tree aos-headless-root rootfs)
                        fakeroot -- mkfs.ext4 ${imageMetadata.ext4Options} -d rootfs -L rootfs -m 1 -q \
                          "$out/root.img" "''${IMAGE_MB}M"
          '';
        }
      ];
    };
  # Assertions use a small read-only virtio block device on both supported VMMs.
  mkFirecrackerTestInput = testScript:
    pkgs.mkDerivation {
      pname = "fc-test-input";
      version = "0";
      src = null;
      test = "set -e\n" + testScript;
      passAsFile = ["test"];
      buildDeps = [pkgs.e2fsprogs pkgs.coreutils pkgs.fakeroot pkgs.python3];
      phases = [
        {
          name = "input";
          script = ''
            mkdir -p input "$out"
            cp "$testPath" input/test
            image_mib=$(( ($(stat -c %s input/test) + 1048575) / 1048576 + 8 ))
            ${imageMetadata.environment}
            IMAGE_UUID=$(${imageMetadata.command} tree aos-headless-test input)
            fakeroot -- mkfs.ext4 ${imageMetadata.ext4Options} -d input -L aos-test -m 0 -q "$out/test.img" "''${image_mib}M"
          '';
        }
      ];
    };
in {
  inherit mkFirecrackerRootfs mkFirecrackerTestInput;
}
