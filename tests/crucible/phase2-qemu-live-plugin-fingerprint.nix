{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginFingerprint",
  # The Rust control plugin is the single-VM fingerprint AUTHORITY here: it boots
  # the patched QEMU once with `fingerprint=on`, drives the shared-memory quantum
  # hot path to a fixed ascending cadence of aggregate-icount targets, and reads
  # the black-box fingerprint sample it publishes into its per-node slot at each
  # boundary, including a real delivered frame and a scheduler-commanded fault.
  # The whole scenario runs twice (the second under host CPU load) and must
  # reproduce byte-for-byte. A negative-control pass changes the second frame,
  # bisects the real QEMU divergence, and exports both sides' complete raw state.
  # Proves the live half of T-QEMU-11, T-DET-8,
  # T-TIME-8, T-HARN-4/7, and the single-VM slice of T-GHC-15.
  taskIds ? ["T-QEMU-11" "T-DET-8" "T-TIME-8" "T-HARN-4" "T-HARN-6" "T-HARN-7" "T-GHC-15"],
  openTaskIds ? [],
  timeoutSecs ? "240",
  secondRunLoad ? "1",
  probeIcount ? "6000000",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-plugin-fingerprint";
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
    # nohz=off keeps a periodic virtual timer so a busy boot advances steadily
    # through the sampled targets before any idle park.
    GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
    CRUCIBLE_FP_TIMEOUT_SECS = timeoutSecs;
    CRUCIBLE_FP_SECOND_RUN_LOAD = secondRunLoad;
    CRUCIBLE_FP_PROBE_ICOUNT = probeIcount;
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
        name = "run-live-plugin-fingerprint";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-plugin-fingerprint-tests" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            plugin_live_runner::

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-plugin-fingerprint-example" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-fingerprint

          run_dir="$TMPDIR/live-plugin-fingerprint-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-plugin-fingerprint.result"
          timeout -k 15 590 \
            "$TMPDIR/live-plugin-fingerprint-example/debug/examples/crucible-qemu-live-plugin-fingerprint" \
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
          grep -Fxq 'definition_domain=crucible.qemu.rust-plugin-fingerprint.v1' "$report"
          grep -Eq '^definition_digest=[0-9a-f]{64}$' "$report"
          grep -Fxq 'sample_count=5' "$report"
          grep -Fxq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' "$report"
          grep -Fxq 'run_horizon_icount=12000000' "$report"
          grep -Fxq 'vcpu_count=1' "$report"
          grep -Fxq 'rr_switch_quantum=4096' "$report"
          grep -Eq '^matching_final_fingerprint=[0-9a-f]{64}$' "$report"
          grep -Fxq 'deterministic_run_twice=true' "$report"
          grep -Fxq 'second_run_host_load=true' "$report"
          grep -Fxq 'synchronous_oracle_enabled=false' "$report"
          grep -Fxq 'synchronous_oracle_matches_all_samples=false' "$report"
          grep -Fxq 'probe_prefix_equal_at_6000000=true' "$report"
          grep -Eq '^probe_count=[1-9][0-9]*$' "$report"

          oracle_report="$TMPDIR/live-plugin-fingerprint-oracle.result"
          CRUCIBLE_FP_SYNC_ORACLE=1 \
            CRUCIBLE_FP_SECOND_RUN_LOAD=0 \
            timeout -k 15 1190 \
            "$TMPDIR/live-plugin-fingerprint-example/debug/examples/crucible-qemu-live-plugin-fingerprint" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir/oracle" \
            "$GUEST_INITRD" \
            "$GUEST_KERNEL_APPEND" \
            > "$oracle_report"
          cat "$oracle_report"
          grep -Fxq PASS "$oracle_report"
          grep -Fxq 'sample_count=5' "$oracle_report"
          grep -Fxq 'sample_target_icounts=4000000,4000001,8000000,8000001,12000000' "$oracle_report"
          grep -Fxq 'aggregate_icount_equals_target=true' "$oracle_report"
          grep -Fxq 'synchronous_oracle_enabled=true' "$oracle_report"
          grep -Fxq 'synchronous_oracle_matches_all_samples=true' "$oracle_report"

          divergence_report="$TMPDIR/live-plugin-fingerprint-divergence.result"
          CRUCIBLE_FP_DIVERGENCE_DUMP=1 \
            timeout -k 15 1790 \
            "$TMPDIR/live-plugin-fingerprint-example/debug/examples/crucible-qemu-live-plugin-fingerprint" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir/divergence" \
            "$GUEST_INITRD" \
            "$GUEST_KERNEL_APPEND" \
            > "$divergence_report"
          cat "$divergence_report"
          grep -Fxq PASS "$divergence_report"
          grep -Fxq 'divergence_negative_control=true' "$divergence_report"
          grep -Eq '^first_different_icount=[1-9][0-9]*$' "$divergence_report"
          grep -Eq '^state_dump_content_address=blake3:[0-9a-f]{64}$' "$divergence_report"
          grep -Fxq 'first_vcpu_register_files=1' "$divergence_report"
          grep -Fxq 'second_vcpu_register_files=1' "$divergence_report"
          grep -Eq '^first_device_state_bytes=[1-9][0-9]*$' "$divergence_report"
          grep -Eq '^second_device_state_bytes=[1-9][0-9]*$' "$divergence_report"
          grep -Fxq 'both_side_raw_state_dump=true' "$divergence_report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          cp "$oracle_report" "$out/oracle-result"
          cp "$divergence_report" "$out/divergence-result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'proven=rust-plugin-fingerprint-authority,async-digest-worker,synchronous-corpus-identity,periodic-cadence-sampling,frame-delivery-sampling,signal-effect-boundary-sampling,run-twice-determinism,restart-probe-equality,instruction-exact-bisection,both-side-raw-state-dump\n'
          } >> "$out/result"
        '';
      }
    ];
  }
