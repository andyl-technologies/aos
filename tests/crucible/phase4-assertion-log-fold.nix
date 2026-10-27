{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionLogFold",
  taskIds ? ["T-ASRT-8"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  assertionLogFoldTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/assertion_log_fold.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-8 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionLogFold`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/trigger.rs" trigger [
      {
        label = "never evaluated outcome";
        needle = "NeverEvaluated";
      }
      {
        label = "never triggered outcome";
        needle = "NeverTriggered";
      }
      {
        label = "never reached warn outcome";
        needle = "NeverReachedWarn";
      }
      {
        label = "never reached fail outcome";
        needle = "NeverReachedFail";
      }
      {
        label = "never reached fail verdict";
        needle = "HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail";
      }
      {
        label = "shared online evaluator";
        needle = "HostAssertionEvaluator::new";
      }
      {
        label = "offline checker uses same finalizer";
        needle = "finalize_prefix";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/assertion_log_fold.rs" assertionLogFoldTest [
      {
        label = "online/offline distinct never outcome test";
        needle = "online_and_offline_fold_report_distinct_never_outcomes_identically";
      }
      {
        label = "online/offline never evaluated test";
        needle = "online_and_offline_fold_report_never_evaluated_identically";
      }
      {
        label = "implementation taxonomy static test";
        needle = "assertion_log_fold_implementation_exposes_distinct_never_taxonomy";
      }
      {
        label = "whole report equality";
        needle = "assert_eq!(offline, online)";
      }
      {
        label = "streaming online observation";
        needle = "observe_prefix";
      }
      {
        label = "never triggered assertion";
        needle = "HostAssertionOutcomeKind::NeverTriggered";
      }
      {
        label = "never reached warn assertion";
        needle = "HostAssertionOutcomeKind::NeverReachedWarn";
      }
      {
        label = "never reached fail assertion";
        needle = "HostAssertionOutcomeKind::NeverReachedFail";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion log fold import";
        needle = "assertionLogFold = import ./phase4-assertion-log-fold.nix";
      }
      {
        label = "phase4 assertion log fold attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionLogFold\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/tests/assertion_log_fold.rs" assertionLogFoldTest [
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
  then throw "crucible phase4 assertion-log-fold check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-assertion-log-fold";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-assertion-log-fold";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --test assertion_log_fold \
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
            assertion_log_fold=true
            RESULT
          '';
        }
      ];
    }
