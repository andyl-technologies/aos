{pkgs}:
# A real Linux guest workload for live guest-clock and virtio accelerator fault
# acceptance. The fixture reads architecture and POSIX clocks, enumerates the
# production modern virtio-pci device, constructs its real split virtqueue, and
# submits the closed GPU, TPU, and FPGA job schemas over guest DMA.
pkgs.mkDerivation {
  pname = "crucible-qemu-fault-hardware-guest";
  version = "0";
  src = builtins.path {
    path = ./phase2-qemu-fault-hardware-guest.c;
    name = "crucible-qemu-fault-hardware-guest.c";
  };

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  hardeningDisable = ["all"];

  phases = [
    {
      name = "build-guest";
      script = ''
        set -eu
        cp "$src" guest.c
        "$CC" -static -std=c11 -O2 -Wall -Wextra -Werror -o init guest.c
        strip --strip-all init
      '';
    }
    {
      name = "build-initramfs";
      script = ''
        set -eu
        mkdir -p root/proc root/sys
        cp init root/init
        chmod 0755 root/init

        mkdir -p "$out"
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            | pigz -9 -n > "$out/initrd.img"
        )
        test -s "$out/initrd.img"

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=diskless-linux-initramfs
        guest_license=GPL-2.0-only
        guest_clock_workload=architecture-counter-posix-clock-timer
        guest_accelerator_transport=modern-virtio-pci-split-virtqueue
        guest_accelerator_jobs=gpu-vector-add,tpu-matrix-multiply,fpga-lookup-table
        EVIDENCE
      '';
    }
  ];
}
