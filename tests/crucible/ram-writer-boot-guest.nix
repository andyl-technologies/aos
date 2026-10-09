# Bootable writer PID 1; the genuine owner remains responsible for VM admission.
{pkgs}: let
  programs = import ./ram-writer-families-guest.nix {inherit pkgs;};
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  resetRom = import ./ram-reset-rom-writer.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-ram-writer-boot-initramfs";
    version = "0";
    src = ./ram-writer-boot-init.c;
    buildDeps = [pkgs.coreutils pkgs.cpio pkgs.pigz pkgs.python3];
    phases = [
      {
        name = "build-and-check-writer-boot-assets";
        script = ''
          set -eu
          cc -std=c11 -static -O2 -Wall -Wextra -Werror "$src" -o init
          mkdir include
          cp "$src" include/ram-writer-boot-init.c
          cc -std=c11 -static -O2 -Wall -Wextra -Werror \
            -I "$PWD/include" ${./ram-writer-boot-control.c} -o relay-control
          ${pkgs.python3}/bin/python3 ${./ram-writer-boot-test.py} \
            --relay "$PWD/relay-control" --writer ${programs}/writer-guest \
            --production-init "$PWD/init" > local-controls.json

          mkdir -p root/dev root/proc root/sys "$out"
          install -m 555 init root/init
          cp ${programs}/writer-guest root/writer-guest
          cp ${programs}/dma-writer-guest root/dma-writer-guest
          # cpio's reproducible mode leaves file timestamps intact.
          find root -exec touch -h --date=@1 {} +
          (
            cd root
            find . -print0 | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | pigz -9 -n > "$out/initrd.img"
          )
          test -s "$out/initrd.img"
          cp local-controls.json "$out/local-controls.json"
          cat > "$out/boot-contract.txt" <<'CONTRACT'
          architecture=x86_64
          kernel=existing-AOS-linux-with-proc-sysfs-devtmpfs-virtio-blk
          case=exactly-one-crucible.writer=CPU_CASE-or-dma-virtio-kernel-token
          console=ttyS0-output-only-no-host-input
          boundaries=flight.ready-sequences-2-3-4-before-W-Z-Q-or-W-R-Q
          dma=original-private-writable-copy-of-native-root-image-as-vda
          reset=separate-generic-loader-firmware-route-still-needs-managed-command-boundary
          fork=host-must-capture-and-restore-canonical-stopped-VM-and-original-pipe-state
          retirement=genuine-original-host-owner-no-guest-refund-or-new-timeout
          qualification=assets-and-local-controls-only-no-deployed-VM-result
          CONTRACT
        '';
      }
    ];
    passthru = {
      inherit programs rootImage resetRom;
      kernel = pkgs.linux;
    };
  }
