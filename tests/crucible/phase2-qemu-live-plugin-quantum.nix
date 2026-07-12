{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginQuantum",
  # T-PLUG-7 and T-TIME-5/7 (idle-jump advancement) stay OPEN: the gate proves
  # ceiling ownership, idle park, and deadline introspection live, but the QEMU-
  # side queued-time-advance completion defect blocks the idle-jump itself.
  #
  # This gate's deadline-introspection evidence equally satisfies T-TIME-6 (the
  # virtual-time-layer twin of T-PLUG-6); its flip is deferred pending the
  # phase1-clock-deadline / phase1-layer0-determinism open-set reconciliation.
  taskIds ? ["T-PLUG-4" "T-PLUG-5" "T-PLUG-6"],
  openTaskIds ? ["T-PLUG-7" "T-TIME-5" "T-TIME-7"],
  # Scheduler tuning for the idle Linux guest, which boots to a fully idle kernel
  # in the low tens of millions of icount.
  ceilingStep ? "4000000",
  maxSearch ? "80000000",
  idleHorizonMargin ? "40000000",
  minIdleSpeedup ? "4",
  quantumTimeoutSecs ? "250",
  # Run the whole scenario twice, the second run under host CPU load, and require
  # byte-identical idle observations — the boot-phase clock-ownership determinism
  # evidence for T-PLUG-4.
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
    pname = "crucible-phase2-qemu-live-plugin-quantum";
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
    # nohz=off keeps a periodic virtual timer so the idle kernel has a concrete
    # next deadline for the plugin to introspect.
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_QUANTUM_CEILING_STEP = ceilingStep;
    CRUCIBLE_QUANTUM_MAX_SEARCH = maxSearch;
    CRUCIBLE_QUANTUM_IDLE_HORIZON_MARGIN = idleHorizonMargin;
    CRUCIBLE_QUANTUM_MIN_IDLE_SPEEDUP = minIdleSpeedup;
    CRUCIBLE_QUANTUM_TIMEOUT_SECS = quantumTimeoutSecs;
    CRUCIBLE_QUANTUM_SECOND_RUN_LOAD = secondRunLoad;
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
        name = "run-live-plugin-quantum-idle";
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
            --target-dir "$TMPDIR/live-plugin-quantum-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-quantum

          run_dir="$TMPDIR/live-plugin-quantum-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-plugin-quantum.result"
          # The diskless firmware-pinned launch attaches no block device, so the
          # Linux guest never issues unserviced virtio-blk I/O during boot. The
          # ROOT_IMAGE argument is unused when CRUCIBLE_QUANTUM_FIRMWARE is set, so
          # pass /dev/null as a placeholder.
          export CRUCIBLE_QUANTUM_FIRMWARE="$GUEST_FIRMWARE"
          timeout -k 15 590 \
            "$TMPDIR/live-plugin-quantum-target/debug/examples/crucible-qemu-live-plugin-quantum" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            /dev/null \
            "$run_dir" \
            "$GUEST_INITRD" \
            "$GUEST_KERNEL_APPEND" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'time_authority=rust-plugin' "$report"
          grep -Fxq 'time_authority_is_rust_plugin=true' "$report"
          # T-PLUG-4: the guest advanced through several busy boot quanta, each
          # stopping exactly at the host-published ceiling, and the two runs (the
          # second under host CPU load) produced byte-identical idle observations.
          grep -Eq '^boot_quantum_count=[1-9][0-9]*$' "$report"
          grep -Fxq 'deterministic_under_host_load=true' "$report"
          grep -Fxq 'host_load_applied=true' "$report"
          # T-PLUG-5/6: the guest parked idle with a computed next virtual-timer
          # deadline (a timer-deadline idle, not an I/O-wait idle).
          grep -Eq '^idle_onset_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^idle_next_deadline_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'idle_kind=timer-deadline' "$report"
          # T-PLUG-7 is descoped: the idle-jump is NOT asserted while the QEMU-side
          # queued-time-advance completion defect is open. The gate records this
          # honestly so it cannot be misread as full idle-jump coverage.
          grep -Fxq 'idle_jump_proven=false' "$report"
          grep -Fxq 'idle_jump_defect=T-PLUG-7-live-idle-jump-advance-completion' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=boot-ceiling-ownership,idle-park,timer-deadline-introspection,run-twice-determinism\n'
            printf 'descoped=idle-jump-advancement-blocked-on-qemu-queued-time-advance-completion\n'
          } >> "$out/result"
        '';
      }
    ];
  }
