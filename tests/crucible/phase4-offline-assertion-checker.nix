{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.offlineAssertionChecker",
  taskIds ? ["T-ASRT-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  offlineAssertionCheckerTest = builtins.readFile ../../crates/crucible/tests/offline_assertion_checker.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-7 completion note";
        needle = "Completed by `checks.crucible.phase4.offlineAssertionChecker`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "offline assertion checker";
        needle = "pub struct OfflineAssertionChecker";
      }
      {
        label = "recorded assertion log";
        needle = "pub struct RecordedAssertionLog";
      }
      {
        label = "offline checker error";
        needle = "pub enum OfflineAssertionCheckError";
      }
      {
        label = "offline default check method";
        needle = "pub fn check_run";
      }
      {
        label = "offline oracle check method";
        needle = "pub fn check_run_with_oracle";
      }
      {
        label = "recorded event-log input";
        needle = "&[SchedulerEventLogEntry]";
      }
      {
        label = "recorded offset input";
        needle = "from_segments";
      }
      {
        label = "recorded offset accessor";
        needle = "pub fn event_log_offset";
      }
      {
        label = "missing offset diagnostic";
        needle = "MissingEventLogOffset";
      }
      {
        label = "checked prefix reconstruction";
        needle = "condition_prefix_from_recorded_entries";
      }
      {
        label = "every retained prefix fold";
        needle = "for index in 0..event_log.len()";
      }
      {
        label = "online evaluator reuse";
        needle = "HostAssertionEvaluator::new";
      }
      {
        label = "terminal prefix finalization";
        needle = "finalize_prefix";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "offline checker export";
        needle = "OfflineAssertionChecker";
      }
      {
        label = "recorded log export";
        needle = "RecordedAssertionLog";
      }
      {
        label = "offline error export";
        needle = "OfflineAssertionCheckError";
      }
    ]
    ++ failuresFor "crates/crucible/tests/offline_assertion_checker.rs" offlineAssertionCheckerTest [
      {
        label = "online/offline equality test";
        needle = "offline_assertion_checker_matches_online_report_for_recorded_log";
      }
      {
        label = "amended idempotent regrade test";
        needle = "offline_assertion_checker_regrades_amended_properties_idempotently";
      }
      {
        label = "invalid recorded log rejection test";
        needle = "offline_assertion_checker_rejects_invalid_recorded_log";
      }
      {
        label = "custom host oracle test";
        needle = "offline_assertion_checker_uses_custom_host_oracle_over_recorded_state";
      }
      {
        label = "custom oracle missing offset test";
        needle = "offline_assertion_checker_requires_offsets_for_custom_host_oracle";
      }
      {
        label = "custom oracle empty offset test";
        needle = "offline_assertion_checker_preserves_empty_run_offset_for_custom_oracle";
      }
      {
        label = "no guest reexecution static test";
        needle = "offline_assertion_checker_implementation_reads_log_without_guest_reexecution";
      }
      {
        label = "whole report equality";
        needle = "assert_eq!(offline, online)";
      }
      {
        label = "byte-identical idempotence";
        needle = "assert_eq!(first, second)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 offline assertion checker import";
        needle = "offlineAssertionChecker = import ./phase4-offline-assertion-checker.nix";
      }
      {
        label = "phase4 offline assertion checker attr path";
        needle = "attrPath = \"checks.crucible.phase4.offlineAssertionChecker\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/offline_assertion_checker.rs" offlineAssertionCheckerTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 offline-assertion-checker check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-offline-assertion-checker";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
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
          name = "run-offline-assertion-checker";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-offline-assertion-checker-target" \
              -p crucible \
              --test offline_assertion_checker \
              --test host_side_assertions \
              --test guest_marker_assertions \
              -- --test-threads=1
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
            tasks=${taskList}
            offline_assertion_checker=true
            RESULT
          '';
        }
      ];
    }
