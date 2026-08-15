{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveFaultHardware",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  faultHardwareGuest = import ./phase2-qemu-fault-hardware-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-fault-hardware";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_INITRD = "${faultHardwareGuest}/initrd.img";
    ATTR_PATH = attrPath;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-live-fault-hardware";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          grep -Fxq 'guest_format=diskless-linux-initramfs' \
            ${faultHardwareGuest}/evidence.env
          grep -Fxq 'guest_accelerator_transport=modern-virtio-pci-split-virtqueue' \
            ${faultHardwareGuest}/evidence.env

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-fault-hardware

          run_dir="$TMPDIR/live-fault-hardware-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-fault-hardware.result"
          timeout -k 15 300 \
            "$TMPDIR/live-fault-hardware-target/debug/examples/crucible-qemu-live-fault-hardware" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-fault-hardware' "$report"
          grep -Fxq 'guest_clock_reads=architecture-counter,posix-monotonic,posix-realtime' "$report"
          grep -Fxq 'accelerator_transport=real-modern-virtio-pci' "$report"
          grep -Fxq 'accelerator_jobs=gpu-vector-add,tpu-matrix-multiply,fpga-lookup-table' "$report"
          grep -Fxq 'host_adapter=qemu-live-accelerator-servicer' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          printf 'attr_path=%s\n' "$ATTR_PATH" >> "$out/result"
          printf 'proven=real-linux-clock-observation,real-virtio-pci-discovery,guest-dma,split-virtqueue,gpu-job,tpu-job,fpga-job,fault-free-event-reservation\n' >> "$out/result"
        '';
      }
    ];
  }
