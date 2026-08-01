{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginFingerprintSmp",
  # The Rust control plugin is the multi-vCPU fingerprint AUTHORITY here: it boots
  # the patched QEMU once at `-smp N` with `fingerprint=on` on the multi-threaded
  # S11 guest, drives the shared-memory quantum hot path to a fixed ascending
  # cadence of AGGREGATE-icount targets across all N vCPUs, and reads the black-box
  # fingerprint sample it publishes into its per-node slot at each boundary. The
  # sample carries every vCPU's register-file digest (exactly 0..N) plus the
  # authoritative round-robin cursor. The whole scenario runs twice (the second
  # under host CPU load) and must reproduce byte-for-byte.
  #
  # This is the M3 live keystone: the Rust plugin drives a real multi-vCPU busy
  # guest deterministically at the frozen -smp 4 pin. It certifies live (both this
  # -smp 4 committed run and a proven -smp 2 run):
  #   T-TIME-9  aggregate-icount node clock (per-vCPU retired sums to aggregate),
  #   T-QEMU-16 N-vCPU fingerprint (all 0..N register files + RR cursor in digest),
  #   T-PLUG-26 per-vCPU register + RR-cursor reads feeding the fingerprint.
  # It contributes partial live evidence to T-PLUG-24 (RR sub-division + per-vCPU
  # register/cursor determinism; the all-halted node-idle-at-N exercise is deferred
  # with the idle-warp window) and T-DET-30 (per-vCPU register/entropy uniformity).
  # Per the M3 determinism-scope decision the run-twice assertion covers the FULL
  # component set — per-vCPU registers + guest-RAM digest + device-state digest, in
  # busy windows — but NOT terminal-state (VMState-serialization) byte-identity,
  # which waits on the open idle-warp / device-VMState defects.
  smpVcpus ? "4",
  memoryMib ? "256",
  taskIds ? ["T-TIME-9" "T-QEMU-16" "T-PLUG-24" "T-PLUG-26"],
  openTaskIds ? [],
  timeoutSecs ? "300",
  secondRunLoad ? "1",
  probeIcount ? "6000000",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  s11GuestCheck = import ./phase0-s11.nix {
    inherit pkgs lib;
    stopAt = 1;
  };
  s11Guest = s11GuestCheck.passthru.crucibleSmpGuest;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-plugin-fingerprint-smp";
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

    GUEST_KERNEL = builtins.toString s11Guest.kernel;
    GUEST_INITRD = "${s11Guest.initramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    # nohz=off keeps a periodic virtual timer so the busy multi-vCPU boot advances
    # steadily through the sampled aggregate-icount targets before any idle park.
    GUEST_KERNEL_APPEND = "${s11Guest.kernelAppend} nohz=off";
    CRUCIBLE_FP_TIMEOUT_SECS = timeoutSecs;
    CRUCIBLE_FP_SECOND_RUN_LOAD = secondRunLoad;
    CRUCIBLE_FP_PROBE_ICOUNT = probeIcount;
    CRUCIBLE_FP_SMP_VCPUS = smpVcpus;
    CRUCIBLE_FP_MEMORY_MIB = memoryMib;
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
        name = "run-live-plugin-fingerprint-smp";
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
            --target-dir "$TMPDIR/live-plugin-fingerprint-smp-example" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-fingerprint

          run_dir="$TMPDIR/live-plugin-fingerprint-smp-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-plugin-fingerprint-smp.result"
          timeout -k 15 590 \
            "$TMPDIR/live-plugin-fingerprint-smp-example/debug/examples/crucible-qemu-live-plugin-fingerprint" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            "$GUEST_INITRD" \
            "$GUEST_KERNEL_APPEND" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'fingerprint_authority=rust-plugin' "$report"
          grep -Fxq 'definition_domain=crucible.qemu.rust-plugin-fingerprint.v2' "$report"
          grep -Eq '^definition_digest=[0-9a-f]{64}$' "$report"
          grep -Fxq 'sample_count=5' "$report"
          grep -Fxq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' "$report"
          grep -Fxq 'run_horizon_icount=12000000' "$report"
          grep -Fxq "vcpu_count=$CRUCIBLE_FP_SMP_VCPUS" "$report"
          grep -Fxq "memory_mib=$CRUCIBLE_FP_MEMORY_MIB" "$report"
          grep -Fxq 'rr_switch_quantum=4096' "$report"
          grep -Eq '^matching_final_fingerprint=[0-9a-f]{64}$' "$report"
          grep -Fxq 'deterministic_run_twice=true' "$report"
          grep -Fxq 'second_run_host_load=true' "$report"
          grep -Eq "^probe_prefix_equal_at_[0-9]+=true$" "$report"
          grep -Eq '^probe_count=[1-9][0-9]*$' "$report"
          # Full-component run-twice determinism (registers + RR cursor + RAM +
          # device state), plus the raw-vs-logical aggregation regression guard:
          # every busy-window boundary's aggregate node icount equals its exact
          # target. (Under single-threaded RR icount QEMU keeps one global counter,
          # so the per-vCPU introspection retired stamp is a deterministic constant
          # and the per-vCPU progress that exists is the sampled RR cursor.)
          grep -Fxq 'aggregate_icount_equals_target=true' "$report"
          grep -Fxq 'rr_cursor_matches_run_twice=true' "$report"
          grep -Fxq 'per_vcpu_registers_match_run_twice=true' "$report"
          grep -Fxq 'guest_ram_digest_matches_run_twice=true' "$report"
          grep -Fxq 'device_state_digest_matches_run_twice=true' "$report"
          # Every boundary reports the aggregate icount, RR cursor, and N registers.
          grep -Eq "^sample\[0\]_aggregate_icount=[0-9]+ rr_current_vcpu=[0-9]+ rr_position_in_quantum=[0-9]+ vcpu_register_count=$CRUCIBLE_FP_SMP_VCPUS$" "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=rust-plugin-multi-vcpu-fingerprint-authority,aggregate-icount-hits-exact-target,rr-cursor-determinism,full-component-run-twice-determinism\n'
          } >> "$out/result"
        '';
      }
    ];
  }
