# Shared diskless sim-mode workload initramfs for drop-one behavioral
# discrimination. A guest booted under `-accel sim -icount shift=0,sleep=off`
# reads a set of guest-visible determinism observables (virtio-rng /dev/hwrng,
# the getrandom-seeded boot_id, a /dev/urandom draw, the RTC, and an
# auto-generated NVMe namespace NGUID) and prints them to the serial console;
# the caller hashes those lines into a per-run fingerprint. The NGUID is a
# live consumer of QEMU's process-global GLib PRNG, so it discriminates the
# deterministic-GLib-seeding patch rather than relying on a source fixture.
#
# It deliberately avoids Crucible's shmem block/9p devices: under the sim
# accelerator those devices block on I/O without a host runtime servicing the
# ring. A tiny ordinary NVMe image is attached only to expose its generated
# namespace identifier; no guest data I/O is part of the fingerprint.
{
  pkgs,
  lib,
}: let
  nvmeNguidProbe = pkgs.mkDerivation {
    pname = "crucible-nvme-nguid-probe";
    version = "0";
    src = null;
    phases = [
      {
        name = "build-nvme-nguid-probe";
        script = ''
          cat > nvme-nguid.c <<'SOURCE'
          #include <fcntl.h>
          #include <linux/nvme_ioctl.h>
          #include <stdint.h>
          #include <stdio.h>
          #include <string.h>
          #include <sys/ioctl.h>
          #include <unistd.h>

          int main(void)
          {
              unsigned char identify[4096];
              struct nvme_admin_cmd command;
              int fd;
              size_t index;

              memset(identify, 0, sizeof(identify));
              memset(&command, 0, sizeof(command));
              fd = open("/dev/nvme0", O_RDONLY);
              if (fd < 0) {
                  return 1;
              }
              command.opcode = 0x06;
              command.nsid = 1;
              command.addr = (uint64_t)(uintptr_t)identify;
              command.data_len = sizeof(identify);
              command.cdw10 = 0;
              if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &command) < 0) {
                  close(fd);
                  return 1;
              }
              close(fd);
              for (index = 104; index < 120; index++) {
                  printf("%02x", identify[index]);
              }
              putchar('\n');
              return 0;
          }
          SOURCE
          mkdir -p "$out/bin"
          cc -std=c11 -O2 -Wall -Wextra -Werror nvme-nguid.c \
            -o "$out/bin/nvme-nguid"
        '';
      }
    ];
  };
  deps = [pkgs.bash pkgs.coreutils pkgs.grep pkgs.kmod pkgs.linux nvmeNguidProbe pkgs.util-linux];
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
          modprobe nvme 2>/dev/null || true
          i=0; while [ \$i -lt 100 ] && [ ! -c /dev/hwrng ]; do sleep 0.05; i=\$((i+1)); done
          if [ -c /dev/hwrng ]; then echo "SIMBOOT:HWRNG=\$(head -c 8 /dev/hwrng | od -An -tx1 | tr -d ' ')"; else echo SIMBOOT:NOHWRNG; fi
          echo "SIMBOOT:BOOTID=\$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d -)"
          echo "SIMBOOT:GRND=\$(head -c 8 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' ')"
          echo "SIMBOOT:RTC=\$(cat /sys/class/rtc/rtc0/time 2>/dev/null; cat /sys/class/rtc/rtc0/date 2>/dev/null)"
          i=0; mac=""; while [ \$i -lt 1000 ] && [ -z "\$mac" ]; do
            mac=\$(cat /sys/class/net/*/address 2>/dev/null | grep -v '^00:00:00' | sort | tr -d : | tr '\n' ' ')
            [ -n "\$mac" ] || sleep 0.05
            i=\$((i+1))
          done
          echo "SIMBOOT:MAC=\$mac"
          i=0; while [ \$i -lt 1000 ] && [ ! -c /dev/nvme0 ]; do sleep 0.05; i=\$((i+1)); done
          echo "SIMBOOT:NVME_NGUID=\$(nvme-nguid 2>/dev/null)"
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
    # sim_fingerprint QEMU FIRMWARE [RTC_CLOCK] [SEED_MODE] [SMP].
    # RTC_CLOCK defaults to vm; pass "host" to expose the sim-forces-virtual RTC
    # patch (0007). SEED_MODE defaults to seeded and may be "none" to exercise
    # the sim fail-closed policy for unseeded guest random (0008). SMP defaults
    # to one and is available to multi-vCPU discriminators.
    sim_fingerprint() {
      local qemu="$1" firmware="$2" rtc_clock="''${3:-vm}"
      local seed_mode="''${4:-seeded}" smp="''${5:-1}" seed_arg ser nvme_image
      ser="$TMPDIR/sim-fp.$$.$RANDOM.serial"
      nvme_image="$TMPDIR/sim-fp.$$.$RANDOM.nvme"
      rm -f "$ser"
      truncate -s 8M "$nvme_image"
      if [ "$seed_mode" = seeded ]; then
        seed_arg="-seed 0x0010c001"
      else
        seed_arg=""
      fi
      timeout 180 "$qemu" -L "$firmware" \
        -nodefaults -no-user-config -display none -monitor none -machine q35 \
        -accel sim,thread=single -icount shift=0,sleep=off,align=off \
        -cpu qemu64,-rdrand,-rdseed -m 1024 -smp "$smp" \
        -rtc "base=2026-01-01T00:00:00,clock=$rtc_clock" $seed_arg \
        -object rng-builtin,id=simrng0 -device virtio-rng-pci,rng=simrng0 \
        -netdev user,id=simnet0 -device virtio-net-pci,netdev=simnet0 \
        -drive "file=$nvme_image,if=none,format=raw,id=simnvme0" \
        -device nvme,serial=crucible0001,id=simnvme \
        -device nvme-ns,drive=simnvme0,bus=simnvme,nguid=auto \
        -kernel "$SIM_KERNEL" -initrd "$SIM_INITRD" \
        -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet net.ifnames=0" \
        -chardev file,id=simser0,path="$ser" -serial chardev:simser0 -no-reboot \
        > /dev/null 2> "$ser.qemu-stderr" || true
      tr -d '\r' < "$ser" > "$ser.normalized"
      if ! grep -q '^SIMBOOT:DONE$' "$ser.normalized" 2>/dev/null; then
        cat "$ser.qemu-stderr" >&2 || true
        tail -100 "$ser.normalized" >&2 || true
        return 0
      fi
      # The kernel mixes boot-internal timing into boot_id and /dev/urandom
      # after additional PCI devices are present. They remain diagnostic serial
      # output, but the discriminator hashes only direct QEMU-controlled
      # observables.
      observables=$(grep -E 'SIMBOOT:(HWRNG|RTC|MAC|NVME_NGUID)=' "$ser.normalized" 2>/dev/null)
      for observable in HWRNG RTC MAC NVME_NGUID; do
        if ! printf '%s\n' "$observables" | grep -Eq "^SIMBOOT:$observable=.+$"; then
          echo "missing non-empty SIMBOOT:$observable observable" >&2
          tail -100 "$ser.normalized" >&2 || true
          return 0
        fi
      done
      if [ "''${SIM_DEBUG_OBSERVABLES:-0}" = 1 ]; then
        printf '%s\n' "$observables" >&2
      fi
      printf '%s\n' "$observables" | sha256sum | cut -c1-16
    }
  '';
in {
  inherit initramfs probeLib;
}
