{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveTerminalTargets",
  taskIds ? ["T-QEMU-11" "T-QEMU-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  s11GuestCheck = import ./phase0-s11.nix {
    inherit pkgs lib;
    stopAt = 1;
  };
  s11Guest = s11GuestCheck.passthru.crucibleSmpGuest;

  # Exact bytes produced by GuestEntropySeed::from_scenario_seed(0x0010_c001).
  guestSeed = pkgs.mkDerivation {
    pname = "crucible-live-terminal-targets-seed";
    version = "0";
    src = null;
    phases = [
      {
        name = "materialize-seed";
        script = ''
          set -eu
          mkdir -p "$out"
          printf '\070\130\271\071\150\151\146\007\322\313\013\266\024\253\256\032\114\205\011\004\350\142\140\177\061\235\337\203\174\344\353\345' \
            > "$out/seed.bin"
          test "$(wc -c < "$out/seed.bin")" -eq 32
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-terminal-targets";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.crucible-qemu-trace-plugin
      pkgs.rust
      pkgs.sed
    ];

    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_INITRD = "${s11Guest.initramfs}/initrd.img";
    GUEST_KERNEL = builtins.toString s11Guest.kernel;
    GUEST_KERNEL_APPEND = s11Guest.stockEntropyKernelAppend;
    GUEST_SEED = "${guestSeed}/seed.bin";
    QEMU_BINARY = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    TRACE_PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    TASK_IDS = builtins.concatStringsSep "," taskIds;
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
        name = "run-live-terminal-targets";
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
            --target-dir "$TMPDIR/live-terminal-target-tests" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            terminal_target::tests

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-terminal-target-example" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-terminal-targets

          artifact_root="$TMPDIR/live-terminal-targets"
          report="$TMPDIR/live-terminal-targets.result"
          "$TMPDIR/live-terminal-target-example/debug/examples/crucible-qemu-live-terminal-targets" \
            "$QEMU_BINARY" \
            "$GUEST_FIRMWARE" \
            "$vmlinuz" \
            "$GUEST_INITRD" \
            "$GUEST_SEED" \
            "$TRACE_PLUGIN" \
            "$artifact_root" \
            "$GUEST_KERNEL_APPEND" \
            > "$report"

          grep -Fxq PASS "$report"
          grep -Fxq 'preflight_qmp_state=prelaunch' "$report"
          grep -Fxq 'preflight_qmp_running=false' "$report"
          grep -Fxq 'preflight_shutdown=natural-success' "$report"
          grep -Fxq 'terminal_qmp_state_all=paused' "$report"
          grep -Fxq 'terminal_qmp_running_all=false' "$report"
          grep -Fxq 'terminal_shutdown_all=natural-success' "$report"
          grep -Fxq 'terminal_publication_import_all=true' "$report"
          grep -Fxq 'terminal_sample_icounts=1,50001,100000' "$report"
          grep -Fxq 'same_target_state_fingerprints_equal=true' "$report"
          grep -Fxq 'exact_targets_distinct=true' "$report"
          grep -Fxq 'target_state_fingerprints_distinct=true' "$report"
          grep -Fxq 'target_guest_memory_component_digests_nonconstant=true' "$report"
          grep -Fxq 'target_device_state_component_digests_nonconstant=true' "$report"
          grep -Fxq 'fresh_attempt_directories_distinct=true' "$report"
          grep -Fxq 'fresh_control_identities_distinct=true' "$report"
          grep -Fxq 'fresh_invocation_identities_distinct=true' "$report"
          grep -Fxq 'fresh_raw_argv_identities_distinct=true' "$report"
          grep -Fxq 'negative_zero_target_rejected=true' "$report"
          grep -Fxq 'negative_overshoot_rejected=true' "$report"
          grep -Fxq 'negative_scenario_drift_rejected=true' "$report"
          grep -Fxq 'no_rejected_request_attempt_allocated=true' "$report"
          grep -Fxq 'definition_and_run_inputs_fixed=true' "$report"
          grep -Fxq 'second_ordinal_repeat=true' "$report"
          grep -Fxq 'vcpu_count=2' "$report"
          grep -Fxq 'rr_switch_quantum=4096' "$report"
          grep -Fxq 'scope=isolated-current-state-target-foundation-not-cumulative-prefix-or-refinement' "$report"
          grep -Eq '^definition_digest=[0-9a-f]{64}$' "$report"
          grep -Eq '^fixed_run_digest=[0-9a-f]{64}$' "$report"
          for target in 1 50001 100000; do
            grep -Eq "^target_''${target}_state_fingerprint=[0-9a-f]{64}$" "$report"
            grep -Eq "^target_''${target}_guest_memory_component_digest=[0-9a-f]{64}$" "$report"
            grep -Eq "^target_''${target}_device_state_component_digest=[0-9a-f]{64}$" "$report"
          done

          test -s "$artifact_root/preflight/attempt-00000001/preflight.jsonl"
          for attempt in 00000001 00000002 00000003 00000004 00000005 00000006; do
            test -s "$artifact_root/runs/attempt-$attempt/trace.jsonl"
          done
          test "$(find "$artifact_root/runs" -mindepth 1 -maxdepth 1 -type d -name 'attempt-*' | wc -l)" -eq 6
          test ! -e "$artifact_root/runs/attempt-00000007"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'guest_artifacts=actual-immutable-store-inputs\n'
            printf 'terminal_state=actual-all-vcpu-ram-vmstate-rr-import\n'
            printf 'qmp_connector=typed-unix-production\n'
            printf 'process_owner=live-observation-process\n'
          } >> "$out/result"
        '';
      }
    ];
  }
