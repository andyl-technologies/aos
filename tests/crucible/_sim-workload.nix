# Shared diskless sim-mode workload initramfs for drop-one behavioral
# discrimination. A guest booted under `-accel sim -icount shift=0,sleep=off`
# reads a set of guest-visible determinism observables (virtio-rng /dev/hwrng,
# the getrandom-seeded boot_id, a /dev/urandom draw, and the RTC) and prints
# them to the serial console; the caller hashes those lines into a per-run
# fingerprint.
#
# DISKLESS by construction: under the sim accelerator a virtio-blk/9p device
# blocks on I/O with no host runtime servicing the shmem ring, so the guest
# stalls; this workload uses only kernel + initramfs + virtio-rng (firmware-
# pinned diskless profile), which boots to userspace in ~23s and reaches the
# observables. Block/9p-effect patches are therefore not discriminable here.
{
  pkgs,
  lib,
}: let
  deps = [pkgs.bash pkgs.coreutils pkgs.kmod pkgs.linux pkgs.util-linux];
  depPaths = builtins.concatStringsSep ":" (builtins.concatMap (d: ["${d}/bin" "${d}/sbin"]) deps);
  graphPairs = lib.concatLists (lib.imap (i: d: ["closure-${toString i}" d]) deps);
  initramfs = pkgs.mkDerivation {
    pname = "crucible-sim-workload-initramfs";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.cpio pkgs.findutils pkgs.grep pkgs.pigz];
    exportReferencesGraph = graphPairs;
    phases = [
      {
        name = "build-sim-workload-initramfs";
        script = ''
          set -eu
          grep -h '^/nix/store/' closure-* | sort -u > closure-paths
          mkdir -p root/bin root/sbin root/proc root/sys root/dev root/tmp root/run root/nix/store root/lib
          while IFS= read -r p; do cp -a "$p" root"$p"; done < closure-paths
          ln -sfn ${pkgs.bash}/bin/bash root/bin/sh
          ln -sfn ${pkgs.linux}/lib/modules root/lib/modules
          cat > root/init <<INIT
          #!${pkgs.bash}/bin/bash
          export PATH="/bin:/sbin:${depPaths}"
          mount -t proc proc /proc; mount -t sysfs sysfs /sys; mount -t devtmpfs devtmpfs /dev
          echo "SIMBOOT:USERSPACE"
          modprobe virtio_rng 2>/dev/null || true
          modprobe virtio_net 2>/dev/null || true
          i=0; while [ \$i -lt 100 ] && [ ! -c /dev/hwrng ]; do sleep 0.05; i=\$((i+1)); done
          if [ -c /dev/hwrng ]; then echo "SIMBOOT:HWRNG=\$(head -c 8 /dev/hwrng | od -An -tx1 | tr -d ' ')"; else echo SIMBOOT:NOHWRNG; fi
          echo "SIMBOOT:BOOTID=\$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d -)"
          echo "SIMBOOT:GRND=\$(head -c 8 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' ')"
          echo "SIMBOOT:RTC=\$(cat /sys/class/rtc/rtc0/time 2>/dev/null; cat /sys/class/rtc/rtc0/date 2>/dev/null)"
          echo "SIMBOOT:MAC=\$(cat /sys/class/net/*/address 2>/dev/null | grep -v '^00:00:00' | sort | tr -d : | tr '\n' ' ')"
          echo SIMBOOT:DONE
          sync; sleep 0.2
          ${pkgs.util-linux}/sbin/poweroff -f 2>/dev/null || reboot -f 2>/dev/null || true
          INIT
          chmod +x root/init
          mkdir -p "$out"
          (cd root; find . -print0 | LC_ALL=C sort -z | cpio --quiet -o -H newc -R +0:+0 --reproducible --null | pigz -9 -n > "$out/initrd.img")
        '';
      }
    ];
  };
  # Shared shell helpers emitted into a sim-probe script: `sim_fingerprint QEMU`
  # boots QEMU once under the sim accelerator with the diskless workload and
  # echoes a 16-hex fingerprint of the guest observable lines (empty on failure).
  probeLib = ''
    SIM_KERNEL=$(ls "${pkgs.linux}/boot/vmlinuz-"* | head -1)
    SIM_INITRD="${initramfs}/initrd.img"
    # sim_fingerprint QEMU FIRMWARE [RTC_CLOCK]. RTC_CLOCK defaults to vm
    # (deterministic virtual clock); pass "host" to expose the sim-forces-virtual
    # RTC patch (0007) -- a variant lacking it then reads host time and diverges.
    # A virtio-net NIC with an auto-assigned MAC (no mac=) exposes the glib-PRNG
    # patch (0005): its MAC is drawn from QEMU's seeded glib PRNG.
    sim_fingerprint() {
      local qemu="$1" firmware="$2" rtc_clock="''${3:-vm}" ser
      ser="$TMPDIR/sim-fp.$$.$RANDOM.serial"
      rm -f "$ser"
      timeout 180 "$qemu" -L "$firmware" \
        -nodefaults -no-user-config -display none -monitor none -machine q35 \
        -accel sim,thread=single -icount shift=0,sleep=off,align=off \
        -cpu qemu64,-rdrand,-rdseed -m 512 -smp 1 \
        -rtc "base=2026-01-01T00:00:00,clock=$rtc_clock" -seed 0x0010c001 \
        -object rng-builtin,id=simrng0 -device virtio-rng-pci,rng=simrng0 \
        -netdev user,id=simnet0 -device virtio-net-pci,netdev=simnet0 \
        -kernel "$SIM_KERNEL" -initrd "$SIM_INITRD" \
        -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0" \
        -chardev file,id=simser0,path="$ser" -serial chardev:simser0 -no-reboot \
        > /dev/null 2>&1 || true
      grep -E 'SIMBOOT:(HWRNG|BOOTID|GRND|RTC|MAC)=' "$ser" 2>/dev/null | sha256sum | cut -c1-16
    }
  '';
in {
  inherit initramfs probeLib;
}
