{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLive9pIo",
  # Certifies real guest 9p I/O over SLOT_9P_IO:
  #   - reference (sim) leg: boots a guest with a crucible-shmem virtio-9p
  #     device + mount initrd, forwards requests to the host 9p sub-node, and
  #     requires deterministic response delivery followed by guest progress;
  #   - scheduler-preemption sim leg: repeats with bounded QEMU preemption and a due response
  #     deliberately delayed in wall time; modeled device latency must match;
  #   - TCG control leg: boots the same guest + 9p device under TCG with no
  #     plugin and requires PID 1's post-mount console marker, proving a real
  #     virtio-9p request/response exchange completed successfully.
  taskIds ? ["T-PLUG-13"],
  openTaskIds ? [],
  # A busy ceiling above the diskless idle onset (~15.8M): the guest boots to
  # userspace and runs its mount workload before it touches 9p, so the op lands
  # far later than a virtio-blk realize-time probe.
  busyCeiling ? "4000000000",
  # This is a per-leg wall-clock safety bound, not modeled time. The first 9p
  # request arrives around 3.33 billion retired instructions and certification
  # then requires the guest to consume the response and close the 4-billion
  # instruction ceiling. Keep enough headroom for loaded or slower builders;
  # determinism is still enforced exclusively in the icount domain.
  ninepTimeoutSecs ? "180",
  secondRunSchedulerPreemption ? "1",
}: let
  liveIoRunner = import ./_live-io-runner.nix {inherit pkgs lib;};
  # A stock kernel with 9p built IN (CONFIG_NET_9P=y / CONFIG_9P_FS=y) on top of
  # the same config the other crucible live gates boot under the sim accelerator.
  # The 9p=y-only `linux-crucible` fixture kernel does not boot under sim (its
  # stripped, no-ACPI config is sim-incompatible), whereas pkgs.linux's config
  # boots reliably under sim, so 9p support is layered onto that instead. Built
  # in means the mount initrd stays tiny -- a large module-loading initrd
  # perturbs the guest's early-boot memory layout under sim.
  ninepKernel = pkgs.linuxWith ''
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_9P_FS=y
    CONFIG_9P_FS_POSIX_ACL=y
    CONFIG_NETFS_SUPPORT=y
  '';

  ninepInitramfs = import ./phase2-qemu-live-9p-io-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-9p-io";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      liveIoRunner
    ];

    GUEST_KERNEL = builtins.toString ninepKernel;
    GUEST_INITRD = "${ninepInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_9P_IO_BUSY_CEILING = busyCeiling;
    CRUCIBLE_9P_IO_TIMEOUT_SECS = ninepTimeoutSecs;
    CRUCIBLE_9P_IO_SECOND_RUN_SCHEDULER_PREEMPTION = secondRunSchedulerPreemption;
    TASK_IDS = taskList;
    OPEN_TASK_IDS = openTaskList;
    ATTR_PATH = attrPath;

    phases = [
      {
        name = "run-live-9p-io";
        script = ''
          set -eu
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          run_dir="$TMPDIR/live-9p-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-9p-io.result"
          # Arg order: QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY INITRD. The
          # initrd is required -- a virtio-9p filesystem is untouched until the
          # guest mounts it.
          timeout -k 15 590 \
            "${liveIoRunner}/bin/crucible-qemu-live-ninep-io" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            "$GUEST_INITRD" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-9p-io' "$report"
          grep -Fxq 'certification=9p-forward-and-completion-under-sim' "$report"
          grep -Fxq 'ninep_ring=SLOT_9P_IO' "$report"
          grep -Fxq 'sim_leg_forwarded=true' "$report"
          grep -Eq '^frames_processed=[1-9][0-9]*$' "$report"
          grep -Eq '^frames_delivered=[1-9][0-9]*$' "$report"
          grep -Eq '^first_request_icount=[0-9]+$' "$report"
          grep -Eq '^first_completion_horizon=[1-9][0-9]*$' "$report"
          grep -Fxq 'last_device_io_active=false' "$report"
          grep -Fxq 'advance_outcome=closed-ceiling' "$report"
          grep -Eq '^ceiling_closure=(retired-to-ceiling|idle-wake-beyond-ceiling)$' "$report"
          grep -Fxq 'guest_progressed_past_ninep_io=true' "$report"
          grep -Fxq 'tcg_control_issued_9p=true' "$report"
          grep -Fxq 'deterministic_under_scheduler_preemption=true' "$report"
          grep -Fxq 'scheduler_preemption_applied=true' "$report"
          grep -Fxq 'host_adversary=bounded-scheduler-preemption' "$report"
          grep -Fxq 'delayed_response_applied=true' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=certifying-live-9p-forward-and-completion\n'
            printf 'proven=live-SLOT_9P_IO-request-servicing,device-horizon-advance,delayed-response-wall-time-inertness,guest-progress,run-twice-observation-determinism,tcg-successful-mount-control\n'
          } >> "$out/result"
        '';
      }
    ];
  }
