{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveBlockIo",
  # Drives real guest block I/O through the mapped quantum hot path. It attaches
  # a crucible-shmem virtio-blk device to the diskless guest and services the
  # guest's virtio-blk probe reads on SLOT_BLK_IO. The plugin must advance a guest
  # blocked on device I/O to the published completion horizon, deliver the
  # response, and continue through bounded scheduler windows. The run repeats
  # under host CPU load and the two runs' block-traffic observations must match.
  taskIds ? ["T-PLUG-12" "T-IO-15" "T-PATCH-9"],
  openTaskIds ? [],
  # The write initramfs reaches PID 1 after kernel device discovery. Keep a
  # bounded but generous virtual horizon so the gate observes its explicit
  # sector write, not only the firmware's early capacity probe.
  busyCeiling ? "10000000000",
  blockTimeoutSecs ? "60",
  secondRunLoad ? "1",
}: let
  liveIoRunner = import ./_live-io-runner.nix {inherit pkgs lib;};
  blockWriteInitramfs = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-block-io";
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
    GUEST_INITRD = "${blockWriteInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_BLOCK_IO_BUSY_CEILING = busyCeiling;
    CRUCIBLE_BLOCK_IO_TIMEOUT_SECS = blockTimeoutSecs;
    CRUCIBLE_BLOCK_IO_SECOND_RUN_LOAD = secondRunLoad;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
    ATTR_PATH = attrPath;

    phases = [
      {
        name = "run-live-block-io";
        script = ''
          set -eu
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          run_dir="$TMPDIR/live-block-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-block-io.result"
          # Arg order: QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD].
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
          grep -Fxq 'block_backend=crucible-shmem-host-servicer' "$report"
          grep -Fxq 'block_ring=SLOT_BLK_IO' "$report"
          # The run completed twice and the two runs' block-traffic observations
          # matched (poll jitter may change only the terminal sample coordinate).
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          grep -Fxq 'delayed_response_applied=true' "$report"
          # Real guest traffic must cross SLOT_BLK_IO, publish a deterministic
          # future completion horizon, complete, and let the guest continue.
          grep -Eq '^frames_processed=[1-9][0-9]*$' "$report"
          grep -Eq '^write_frames_processed=[1-9][0-9]*$' "$report"
          grep -Eq '^frames_delivered=[1-9][0-9]*$' "$report"
          grep -Eq '^advance_outcome=(reached-ceiling|quiesced-after-write)$' "$report"
          grep -Fxq 'guest_progressed_past_block_io=true' "$report"
          grep -Eq '^first_completion_horizon=[1-9][0-9]*$' "$report"
          grep -Eq '^first_request_icount=[0-9]+$' "$report"
          grep -Fxq 'last_device_io_active=false' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=certifying-live-block-io-completion-advance\n'
            printf 'proven=live-SLOT_BLK_IO-request-servicing,successful-zero-byte-write-completion,device-horizon-advance,delayed-response-wall-time-inertness,guest-progress,run-twice-observation-determinism\n'
          } >> "$out/result"
        '';
      }
    ];
  }
