{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveBlockReset",
  taskIds ? ["T-QEMU-0062"],
  openTaskIds ? [],
}: let
  liveIoRunner = import ./_live-io-runner.nix {inherit pkgs lib;};
  resetInitramfs = import ./phase2-qemu-live-block-reset-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-block-reset";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      liveIoRunner
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${resetInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_BLOCK_IO_BUSY_CEILING = "10000000000";
    CRUCIBLE_BLOCK_IO_TIMEOUT_SECS = "120";
    CRUCIBLE_BLOCK_IO_SECOND_RUN_SCHEDULER_PREEMPTION = "0";
    CRUCIBLE_BLOCK_IO_RESET_PROBE = "1";

    phases = [
      {
        name = "run-live-block-reset";
        script = ''
          set -eu
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          run_dir="$TMPDIR/live-block-reset-run"
          report="$TMPDIR/live-block-reset.result"
          mkdir -p "$run_dir"

          timeout -k 15 590 \
            "${liveIoRunner}/bin/crucible-qemu-live-block-io" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            "$GUEST_INITRD" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-block-io' "$report"
          grep -Fxq 'transport_reset_guest_errno=5' "$report"
          grep -Eq '^transport_reset_config_interrupt_delta=[1-9][0-9]*$' "$report"
          grep -Eq '^write_frames_processed=[1-9][0-9]*$' "$report"
          grep -Eq '^frames_delivered=([2-9]|[1-9][0-9]+)$' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' '${attrPath}'
            printf 'task_ids=%s\n' '${builtins.concatStringsSep "," taskIds}'
            printf 'open_task_ids=%s\n' '${builtins.concatStringsSep "," openTaskIds}'
            printf 'scope=live-patched-qemu-block-reset-guest-evidence\n'
            printf 'proven=exact-guest-errno,virtio-config-interrupt,live-reset-event\n'
          } >> "$out/result"
        '';
      }
    ];
  }
