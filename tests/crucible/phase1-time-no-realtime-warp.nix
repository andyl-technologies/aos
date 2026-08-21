{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeNoRealtimeWarp",
  taskIds ? ["T-TIME-5"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  deterministicLaunch = import ./phase1-deterministic-launch.nix {inherit pkgs lib;};
  noWarpWithPlugin = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib;};
  icountNoRealtime = import ./phase1-icount-no-realtime.nix {inherit pkgs lib;};

  qemuLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  qemuTest =
    builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch.rs
    + builtins.readFile ../../crates/crucible-qemu/tests/deterministic_launch/launch_artifacts.rs;
  pluginRoot = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "guest-visible time source policy material";
        needle = "\"guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time\".to_owned(),";
      }
      {
        label = "fixed guest time epoch material";
        needle = "\"guest_time_epoch=fixed-rtc-epoch\".to_owned(),";
      }
      {
        label = "plugin time-control owner material";
        needle = "\"time_control_owner=crucible-qemu-plugin\".to_owned(),";
      }
      {
        label = "time-control acquisition material";
        needle = "\"time_control_acquire=registration-before-first-visible-instruction\".to_owned(),";
      }
      {
        label = "idle warp suppression material";
        needle = "\"idle_warp_under_time_control=suppressed\".to_owned(),";
      }
      {
        label = "virtual-only icount budget material";
        needle = "\"icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL\".to_owned(),";
      }
      {
        label = "realtime deadline ban material";
        needle = "\"realtime_deadline_in_precise_budget=false\".to_owned(),";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/deterministic_launch.rs" qemuTest [
      {
        label = "launch material guest time assertion";
        needle = "guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time";
      }
      {
        label = "launch material time-control assertion";
        needle = "time_control_acquire=registration-before-first-visible-instruction";
      }
      {
        label = "launch material realtime-budget assertion";
        needle = "realtime_deadline_in_precise_budget=false";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginRoot [
      {
        label = "plugin time-control module";
        needle = "pub mod time_control;";
      }
      {
        label = "plugin registration plan export";
        needle = "TimeControlRegistrationPlan";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "canonical registration order";
        needle = "pub const CANONICAL_TIME_CONTROL_REGISTRATION_ORDER";
      }
      {
        label = "time-control request step";
        needle = "PluginRegistrationStep::RequestTimeControl";
      }
      {
        label = "first visible instruction sentinel";
        needle = "PluginRegistrationStep::FirstVisibleInstruction";
      }
      {
        label = "registration order validator";
        needle = "pub fn validate(&self) -> Result<(), TimeControlRegistrationError>";
      }
      {
        label = "duplicate registration step rejection";
        needle = "DuplicateStep";
      }
      {
        label = "time-control before setup";
        needle = "PluginRegistrationStep::RequestTimeControl,\n            PluginRegistrationStep::ReceiveSetup";
      }
      {
        label = "time-control before first instruction";
        needle = "PluginRegistrationStep::RequestTimeControl,\n            PluginRegistrationStep::FirstVisibleInstruction";
      }
      {
        label = "boot barrier before first instruction";
        needle = "PluginRegistrationStep::WaitBootBarrier,\n            PluginRegistrationStep::FirstVisibleInstruction";
      }
      {
        label = "late control rejection test";
        needle = "time_control_registration_order_rejects_late_or_missing_control";
      }
      {
        label = "duplicate control rejection test";
        needle = "time_control_registration_order_rejects_duplicate_steps";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "T-TIME-5 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes no-realtime/no-warp time check";
        needle = "timeNoRealtimeWarp = import ./phase1-time-no-realtime-warp.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 time no-realtime/warp check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-no-realtime-warp";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.rust
        pkgs.sed
      ];

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
          name = "run-time-control-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-no-realtime-warp-target" \
              -p crucible-qemu \
              --test deterministic_launch \
              launch_hash_material_records_every_determinism_field \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-no-realtime-warp-target" \
              -p crucible-qemu-plugin \
              --lib time_control \
              -- --test-threads=1
          '';
        }
        {
          name = "require-leaf-evidence";
          script = ''
            set -eu

            require_line() {
              result="$1/result"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            require_leaf() {
              dependency="$1"
              shift
              require_line "$dependency" "PASS"
              for line in "$@"; do
                require_line "$dependency" "$line"
              done
            }

            require_leaf ${deterministicLaunch} \
              "gate=gate:layer0-determinism" \
              "rtc=base=2026-01-01T00:00:00,clock=vm" \
              "virtual_time_ns=icount<<shift" \
              "tsc_source=icount" \
              "guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time" \
              "guest_time_epoch=fixed-rtc-epoch" \
              "time_control_owner=crucible-qemu-plugin" \
              "time_control_acquire=registration-before-first-visible-instruction" \
              "idle_warp_under_time_control=suppressed" \
              "icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL" \
              "realtime_deadline_in_precise_budget=false"
            require_leaf ${noWarpWithPlugin} \
              "gate=gate:layer0-determinism" \
              "time_control_predicate=qemu_plugin_has_time_control" \
              "wall_clock_warp_under_time_control=false" \
              "notify_preserved_under_time_control=true"
            require_leaf ${icountNoRealtime} \
              "gate=gate:layer0-determinism" \
              "qemu_mode=ICOUNT_PRECISE" \
              "realtime_deadline_in_precise_budget=false"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=partial
            evidence_scope=launch-policy-and-callback-core-model
            gate=gate:layer0-determinism
            guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time
            guest_time_epoch=fixed-rtc-epoch
            time_control_owner=crucible-qemu-plugin
            time_control_acquire=registration-before-first-visible-instruction
            boot_barrier_before_first_visible_instruction=true
            idle_warp_under_time_control=suppressed
            icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL
            realtime_deadline_in_precise_budget=false
            leaf_checks=deterministicLaunch,noWarpWithPlugin,icountNoRealtime
            RESULT
          '';
        }
      ];
    }
