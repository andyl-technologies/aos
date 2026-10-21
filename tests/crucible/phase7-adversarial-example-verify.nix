{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.adversarialExampleVerify",
  taskIds ? ["T-EX-5"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  exampleDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-5 completion note";
        needle = "Completed by `checks.crucible.phase7.adversarialExampleVerify`";
      }
      {
        label = "adversarial verify remains documented";
        needle = "--runs N --adversarial";
      }
      {
        label = "divergence bisection remains documented";
        needle = "divergence-bisection";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "built-in scenario resolver";
        needle = "fn resolve_builtin_example_scenario";
      }
      {
        label = "built-in run scenario variant";
        needle = "RunScenarioRef::BuiltInExample";
      }
      {
        label = "fault campaign built-in verify sample";
        needle = "crucible::FAULT_CAMPAIGN_FAMILY_NAME";
      }
      {
        label = "loaded single-core hostile profile";
        needle = "\"loaded-single-core\"";
      }
      {
        label = "reordered two-core hostile profile";
        needle = "\"reordered-two-core\"";
      }
      {
        label = "loaded many-core hostile profile";
        needle = "\"loaded-many-core\"";
      }
      {
        label = "host profile applied to run plan";
        needle = "host_profile: reduction.host_profile";
      }
      {
        label = "hostile condition reduction expansion";
        needle = "VERIFY_HOSTILE_PROFILES";
      }
      {
        label = "built-in hostile-profile verify test";
        needle = "cli_verify_builtin_corpus_host_profiles";
      }
      {
        label = "divergence report line";
        needle = "verify-divergence";
      }
      {
        label = "bisection state line";
        needle = "verify-bisect-state";
      }
      {
        label = "golden mismatch shape";
        needle = "mismatch=canonical-log+fingerprint-stream";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 adversarial example import";
        needle = "adversarialExampleVerify = import ./phase7-adversarial-example-verify.nix";
      }
      {
        label = "phase7 adversarial example attr path";
        needle = "checks.crucible.phase7.adversarialExampleVerify";
      }
      {
        label = "phase7 adversarial example task id";
        needle = "taskIds = [\"T-EX-5\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 adversarial example verify check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase7-adversarial-example-verify";
      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];
      phases = [
        {
          name = "run-adversarial-example-verify";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible-cli \
              cli_verify_builtin_corpus_host_profiles \
              -- --test-threads=1
            crucible-cargo test \
              -p crucible-cli \
              cli_verify_workflow_localizes_divergence_and_writes_side_artifacts \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            cat > "$out/nix-support/crucible-phase7-adversarial-example-verify.txt" <<REPORT
            attr=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            adversarial_profiles=${builtins.concatStringsSep "," [
              "quiet-single-core"
              "loaded-single-core"
              "reordered-two-core"
              "loaded-many-core"
            ]}
            built_in_verify=true
            divergence_report_shape=golden-tested
            REPORT
          '';
        }
      ];
    }
