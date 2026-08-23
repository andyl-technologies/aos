{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginQuantum",
  # With the QEMU-side queued-time-advance completion fixed (patch 0010
  # icount_advance_virtual_time_to_ns + the patch 0025 reset-vs-advance drain +
  # the plugin max-advance raw-vs-logical ceiling fix, all landed), the plugin
  # drives the full idle hot loop live: it owns the clock, parks idle, introspects
  # the exact deadline, and JUMPS to it through the authorized advance; the guest
  # then wakes at the deadline and re-idles below the published ceiling, never
  # self-extending past it. So this gate proves T-PLUG-4/5/6/7 and T-TIME-5/7 end
  # to end. T-TIME-6 (the deadline-introspection twin of T-PLUG-6) is closed via
  # phase1-clock-deadline.
  taskIds ? ["T-HARN-4" "T-PLUG-4" "T-PLUG-5" "T-PLUG-6" "T-PLUG-7" "T-TIME-5" "T-TIME-7"],
  openTaskIds ? [],
  # Scheduler tuning for the diskless multiboot guest, which arms a periodic PIT
  # deadline and then parks every configured vCPU in HLT.
  ceilingStep ? "4000000",
  maxSearch ? "80000000",
  idleHorizonMargin ? "40000000",
  minIdleSpeedup ? "4",
  quantumTimeoutSecs ? "250",
  # Run the whole scenario twice, the second run under bounded scheduler preemption, and require
  # byte-identical idle observations — the boot-phase clock-ownership determinism
  # evidence for T-PLUG-4.
  secondRunSchedulerPreemption ? "1",
  smpVcpus ? "1",
  memoryMib ? "64",
  customGuestKernel ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  defaultGuest = import ./phase2-qemu-live-plugin-quantum-smp-guest.nix {
    inherit pkgs;
    guestVcpus = builtins.fromJSON smpVcpus;
  };

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

    GUEST_KERNEL =
      if customGuestKernel == null
      then "${defaultGuest}/smp-idle-guest.elf"
      else builtins.toString customGuestKernel;
    GUEST_KERNEL_IS_FILE = "1";
    GUEST_INITRD = "";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_KERNEL_APPEND = "";
    CRUCIBLE_QUANTUM_CEILING_STEP = ceilingStep;
    CRUCIBLE_QUANTUM_MAX_SEARCH = maxSearch;
    CRUCIBLE_QUANTUM_IDLE_HORIZON_MARGIN = idleHorizonMargin;
    CRUCIBLE_QUANTUM_MIN_IDLE_SPEEDUP = minIdleSpeedup;
    CRUCIBLE_QUANTUM_TIMEOUT_SECS = quantumTimeoutSecs;
    CRUCIBLE_QUANTUM_SECOND_RUN_SCHEDULER_PREEMPTION = secondRunSchedulerPreemption;
    CRUCIBLE_QUANTUM_SMP_VCPUS = smpVcpus;
    CRUCIBLE_QUANTUM_MEMORY_MIB = memoryMib;
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
          if [ "$GUEST_KERNEL_IS_FILE" = 1 ]; then
            vmlinuz="$GUEST_KERNEL"
          else
            vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          fi
          test -n "$vmlinuz"

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-plugin-quantum-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --features test-support \
            --example crucible-qemu-live-plugin-quantum

          run_dir="$TMPDIR/live-plugin-quantum-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-plugin-quantum.result"
          # The diskless firmware-pinned launch attaches no block device. The
          # ROOT_IMAGE argument is unused when CRUCIBLE_QUANTUM_FIRMWARE is set,
          # so pass /dev/null as a placeholder.
          export CRUCIBLE_QUANTUM_FIRMWARE="$GUEST_FIRMWARE"
          if [ -n "$GUEST_INITRD" ]; then
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
          else
            timeout -k 15 590 \
              "$TMPDIR/live-plugin-quantum-target/debug/examples/crucible-qemu-live-plugin-quantum" \
              ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              "$vmlinuz" \
              /dev/null \
              "$run_dir" \
              > "$report"
          fi

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'time_authority=rust-plugin' "$report"
          grep -Fxq 'time_authority_is_rust_plugin=true' "$report"
          grep -Fxq "smp_vcpus=$CRUCIBLE_QUANTUM_SMP_VCPUS" "$report"
          grep -Fxq "memory_mib=$CRUCIBLE_QUANTUM_MEMORY_MIB" "$report"
          grep -Fxq 'all_vcpus_halted_idle_observed=true' "$report"
          # T-PLUG-4: the guest advanced through several busy boot quanta, each
          # stopping exactly at the host-published ceiling, and the two runs (the
          # second under bounded scheduler preemption) produced byte-identical idle observations.
          grep -Eq '^boot_quantum_count=[1-9][0-9]*$' "$report"
          grep -Fxq 'deterministic_under_scheduler_preemption=true' "$report"
          grep -Fxq 'scheduler_preemption_applied=true' "$report"
          grep -Fxq 'host_adversary=bounded-scheduler-preemption' "$report"
          # T-HARN-4: the host records each completed production-plugin
          # quantum in the shared canonical schedule vocabulary, replays the
          # exact horizons through SimDouble, and compares the versioned byte
          # encoding. The scheduler-preemption run must reproduce the same schedule too.
          grep -Fxq 'sim_double_schedule_matches=true' "$report"
          grep -Eq '^host_observable_schedule_len=[1-9][0-9]*$' "$report"
          # T-PLUG-5/6 + T-TIME-6: the guest parked idle with a computed next
          # virtual-timer deadline (a timer-deadline idle, not an I/O-wait idle).
          grep -Eq '^idle_onset_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^idle_next_deadline_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'idle_kind=timer-deadline' "$report"
          # T-PLUG-7 + T-TIME-5/7: the plugin advanced virtual time through the
          # authorized idle jump to the exact timer deadline; the guest woke and
          # re-idled below the published ceiling, never self-extending past it. The
          # idle span is a real O(1) jump (idle_icount_span icount in
          # idle_wall_micros of wall time), byte-identical on the second,
          # scheduler-preemptioned run.
          grep -Fxq 'idle_jump_proven=true' "$report"
          grep -Eq '^idle_icount_span=[1-9][0-9]*$' "$report"
          grep -Eq '^idle_wall_micros=[0-9]+$' "$report"
          grep -Eq '^terminal_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^execution_fingerprint=[0-9a-f]{64}$' "$report"
          onset=$(sed -n 's/^idle_onset_icount=//p' "$report")
          terminal=$(sed -n 's/^terminal_icount=//p' "$report")
          test "$terminal" -gt "$onset"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=boot-ceiling-ownership,idle-park,timer-deadline-introspection,authorized-idle-jump-advancement,run-twice-determinism,live-plugin-sim-double-host-schedule-byte-equivalence\n'
          } >> "$out/result"
        '';
      }
    ];
  }
