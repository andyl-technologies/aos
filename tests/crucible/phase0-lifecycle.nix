{
  pkgs,
  lib,
}: let
  fcLib = import ../../lib/testing/firecracker.nix {inherit pkgs lib;};
  crashRootfs = fcLib.mkFirecrackerRootfs {
    pname = "crucible-phase0-lifecycle-crash";
    rootfsDeps = [];
    testScript = ''
      echo "CRUCIBLE_LIFECYCLE_GUEST_CRASH"
      echo 1 > /proc/sys/kernel/sysrq
      echo c > /proc/sysrq-trigger
      sleep 60
    '';
  };
  lifecycleSource = builtins.readFile ./phase0-lifecycle.c;
  hangPluginSource = builtins.readFile ./phase0-lifecycle-hang-plugin.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-lifecycle";
    version = "0";
    src = null;

    lifecycle = lifecycleSource;
    hangPlugin = hangPluginSource;
    passAsFile = [
      "lifecycle"
      "hangPlugin"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.glib
      pkgs.pkg-config
      pkgs.qemu-crucible
    ];

    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    KERNEL = builtins.toString pkgs.linux;
    ROOTFS = builtins.toString crashRootfs;

    phases = [
      {
        name = "build";
        script = ''
          cp "$lifecyclePath" phase0-lifecycle.c
          cp "$hangPluginPath" phase0-lifecycle-hang-plugin.c
          cc -std=c11 -O2 -Wall -Wextra phase0-lifecycle.c -o phase0-lifecycle
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-lifecycle-hang-plugin.c \
            -o phase0-lifecycle-hang-plugin.so
        '';
      }
      {
        name = "run";
        script = ''
          mkdir -p "$out"
          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          cp "$ROOTFS" "$TMPDIR/lifecycle-crash-rootfs.img"
          chmod u+w "$TMPDIR/lifecycle-crash-rootfs.img"
          set +e
          timeout 120 ./phase0-lifecycle \
            "$QEMU" \
            "$vmlinuz" \
            "$TMPDIR/lifecycle-crash-rootfs.img" \
            "$PWD/phase0-lifecycle-hang-plugin.so" \
            "$TMPDIR" \
            > "$out/result"
          lifecycle_status=$?
          set -e
          cat "$out/result"
          if [ "$lifecycle_status" -ne 0 ]; then
            exit "$lifecycle_status"
          fi
          if [ -f "$TMPDIR/lifecycle-guest-crash.serial" ]; then
            cp "$TMPDIR/lifecycle-guest-crash.serial" "$out/guest-crash.serial"
          fi
          cp phase0-lifecycle.c "$out/source.c"
          cp phase0-lifecycle-hang-plugin.c "$out/hang-plugin.c"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 QEMU no-leak lifecycle spike";
    };
  }
