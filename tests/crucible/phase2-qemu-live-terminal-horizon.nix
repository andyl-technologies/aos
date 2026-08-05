{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveTerminalHorizon",
  taskIds ? ["T-QEMU-11" "T-QEMU-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };
  s11GuestCheck = import ./phase0-s11.nix {
    inherit pkgs lib;
    stopAt = 1;
  };
  s11Guest = s11GuestCheck.passthru.crucibleSmpGuest;

  # Exact bytes produced by GuestEntropySeed::from_scenario_seed(0x0010_c001).
  guestSeed = pkgs.mkDerivation {
    pname = "crucible-live-terminal-horizon-seed";
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
    pname = "crucible-phase2-qemu-live-terminal-horizon";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
        '';
      }
      {
        name = "run-live-terminal-horizon";
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
            --target-dir "$TMPDIR/live-terminal-tests" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            terminal_horizon::tests

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-terminal-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-terminal-horizon

          artifact_root="$TMPDIR/live-terminal-horizon"
          report="$TMPDIR/live-terminal-horizon.result"
          "$TMPDIR/live-terminal-target/debug/examples/crucible-qemu-live-terminal-horizon" \
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
          grep -Fxq 'terminal_first_qmp_state=paused' "$report"
          grep -Fxq 'terminal_second_qmp_state=paused' "$report"
          grep -Fxq 'terminal_first_qmp_running=false' "$report"
          grep -Fxq 'terminal_second_qmp_running=false' "$report"
          grep -Fxq 'terminal_first_shutdown=natural-success' "$report"
          grep -Fxq 'terminal_second_shutdown=natural-success' "$report"
          grep -Fxq 'terminal_single_sample_each=true' "$report"
          grep -Fxq 'terminal_sample_icount=100000' "$report"
          grep -Fxq 'terminal_fingerprints_equal=true' "$report"
          grep -Eq '^definition_digest=[0-9a-f]{64}$' "$report"
          grep -Eq '^fixed_run_digest=[0-9a-f]{64}$' "$report"
          grep -Eq '^terminal_final_fingerprint=[0-9a-f]{64}$' "$report"
          grep -Eq '^terminal_raw_ram_digest=[0-9a-f]{64}$' "$report"
          grep -Eq '^terminal_vmstate_digest=[0-9a-f]{64}$' "$report"
          grep -Fxq 'terminal_vmstate_export=true' "$report"
          grep -Fxq 'fresh_attempt_directories_distinct=true' "$report"
          grep -Fxq 'fresh_control_identities_distinct=true' "$report"
          grep -Fxq 'fresh_invocation_identities_distinct=true' "$report"
          grep -Fxq 'fresh_raw_argv_identities_distinct=true' "$report"
          grep -Fxq 'negative_scenario_drift_rejected=true' "$report"
          grep -Fxq 'no_failed_request_attempt_allocated=true' "$report"
          grep -Fxq 'continuing_cadence_rejected=true' "$report"
          grep -Fxq 'second_run_host_load=active' "$report"

          test -s "$artifact_root/preflight/attempt-00000001/preflight.jsonl"
          test -s "$artifact_root/runs/attempt-00000001/trace.jsonl"
          test -s "$artifact_root/runs/attempt-00000002/trace.jsonl"
          test ! -e "$artifact_root/runs/attempt-00000003"

          mkdir -p "$out"
          cp "$report" "$out/result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'scope=terminal-horizon-foundation-not-exact-refinement\n'
            printf 'guest_artifacts=actual-immutable-store-inputs\n'
            printf 'terminal_state=all-vcpu-ram-vmstate-rr\n'
            printf 'qmp_connector=typed-unix-production\n'
            printf 'process_owner=live-observation-process\n'
          } >> "$out/result"
        '';
      }
    ];
  }
