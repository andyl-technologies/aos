{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveBlockIo",
  # Drives real guest block I/O through the mapped quantum hot path. It attaches
  # a crucible-shmem virtio-blk device to the diskless guest and services the
  # guest's virtio-blk probe reads on SLOT_BLK_IO. The plugin must advance a guest
  # blocked on device I/O to the published completion horizon, deliver the
  # response, and continue to the busy ceiling. The run repeats under host CPU
  # load and the two runs' block observations must match.
  taskIds ? ["T-PLUG-12" "T-IO-15" "T-PATCH-9"],
  openTaskIds ? [],
  # A busy ceiling below the diskless-firmware idle onset (~15.8M). The virtio-blk
  # probe issues its reads during early device init, well below this.
  busyCeiling ? "12000000",
  blockTimeoutSecs ? "60",
  secondRunLoad ? "1",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-block-io";
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
    GUEST_INITRD = "${idleInitramfs}/initrd.img";
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
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-live-block-io";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-block-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-block-io

          run_dir="$TMPDIR/live-block-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-block-io.result"
          # Arg order: QEMU PLUGIN KERNEL FIRMWARE RUN_DIRECTORY [INITRD].
          timeout -k 15 590 \
            "$TMPDIR/live-block-io-target/debug/examples/crucible-qemu-live-block-io" \
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
          # The run completed twice and the two runs' block observations were
          # byte-identical (the servicer's determinism invariant: poll jitter never
          # changes which requests are processed or their delivery icounts).
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          grep -Fxq 'delayed_response_applied=true' "$report"
          # Real guest traffic must cross SLOT_BLK_IO, publish a deterministic
          # future completion horizon, complete, and let the guest continue.
          grep -Eq '^frames_processed=[1-9][0-9]*$' "$report"
          grep -Eq '^frames_delivered=[1-9][0-9]*$' "$report"
          grep -Fxq 'advance_outcome=reached-ceiling' "$report"
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
            printf 'proven=live-SLOT_BLK_IO-request-servicing,device-horizon-advance,delayed-response-wall-time-inertness,guest-progress,run-twice-observation-determinism\n'
          } >> "$out/result"
        '';
      }
    ];
  }
