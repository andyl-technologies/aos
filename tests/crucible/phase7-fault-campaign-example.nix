{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.faultCampaignExample",
  taskIds ? ["T-EX-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  exampleDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  exampleCorpus = builtins.readFile ../../crates/crucible/src/example_corpus.rs;
  exampleTest = builtins.readFile ../../crates/crucible/tests/example_corpus.rs;
  sessionRoot = import ./_crucible-session-source.nix {inherit lib;};
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-4 completion note";
        needle = "Completed by `checks.crucible.phase7.faultCampaignExample`";
      }
      {
        label = "generic fuzz caveat";
        needle = "Generic file/hash fuzz execution remains tracked by T-CLI-13.";
      }
      {
        label = "evaluated planted violation";
        needle = "structured guest assertion marker into a violated `no-split-brain`";
      }
      {
        label = "artifact-bound violation reproduction note";
        needle = "reconstructs the replay-side assertion log from that artifact";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "fault campaign family name re-export";
        needle = "FAULT_CAMPAIGN_FAMILY_NAME";
      }
      {
        label = "fault campaign family re-export";
        needle = "fault_campaign_family";
      }
      {
        label = "fault campaign proof re-export";
        needle = "run_fault_campaign_example";
      }
      {
        label = "fault campaign report re-export";
        needle = "FaultCampaignExampleReport";
      }
    ]
    ++ failuresFor "crates/crucible/src/example_corpus.rs" exampleCorpus [
      {
        label = "built-in family name";
        needle = "pub const FAULT_CAMPAIGN_FAMILY_NAME: &str = \"fault-campaign.fam\";";
      }
      {
        label = "family constructor";
        needle = "pub fn fault_campaign_family";
      }
      {
        label = "scenario family type";
        needle = "ScenarioFamily::new";
      }
      {
        label = "generated seed space";
        needle = "SeedSpace::generated";
      }
      {
        label = "density axis";
        needle = "FaultDensityRange::new";
      }
      {
        label = "topology size axis";
        needle = "TopologySizeRange::new(3, 5)";
      }
      {
        label = "topology shape axis";
        needle = "vec![TopologyShape::Ring, TopologyShape::Mesh]";
      }
      {
        label = "no split brain property";
        needle = "no-split-brain";
      }
      {
        label = "coverage feedback from unified event log";
        needle = "EventLogCoverageFeedback::from_event_log";
      }
      {
        label = "basic block coverage event";
        needle = "ObservableEvent::coverage_block";
      }
      {
        label = "coverage marker event";
        needle = "ObservableEvent::coverage_marker";
      }
      {
        label = "coverage-guided fuzz call";
        needle = "family.fuzz_coverage_guided";
      }
      {
        label = "finding artifact capture";
        needle = "FindingReproductionArtifact::capture";
      }
      {
        label = "planted violation evidence helper";
        needle = "fn fault_campaign_violation_evidence";
      }
      {
        label = "planted split-brain guest assertion";
        needle = "GuestAssertionKind::Unreachable";
      }
      {
        label = "host assertion violation proof";
        needle = "HostAssertionOutcomeKind::Violated";
      }
      {
        label = "assertion violation replay checker";
        needle = "check_assertion_violation_reproduction";
      }
      {
        label = "artifact schedule violation encoder";
        needle = "fn fault_campaign_violation_decision";
      }
      {
        label = "artifact-derived replay log";
        needle = "fn fault_campaign_replayed_violation_log_from_artifact";
      }
      {
        label = "artifact schedule violation point";
        needle = "FAULT_CAMPAIGN_VIOLATION_POINT";
      }
      {
        label = "artifact-bound assertion replay";
        needle = "AssertionViolationArtifactReplay::from_artifact";
      }
      {
        label = "violation report in finding fingerprint";
        needle = "fault_campaign_finding_fingerprint(&discovered_iteration, &violation.report)";
      }
      {
        label = "unified fuzz validation";
        needle = "UnifiedGraphOperationEvidence::CoverageGuidedFuzzing";
      }
      {
        label = "unified reproduction validation";
        needle = "UnifiedGraphOperationEvidence::ReproductionArtifact";
      }
      {
        label = "save operation";
        needle = "graph.save(&store, &pre_failure)";
      }
      {
        label = "resume checkpoint operation";
        needle = "graph.resume_checkpoint(save.checkpoint)";
      }
      {
        label = "fork operation";
        needle = "let fork = graph.fork";
      }
      {
        label = "alternate neighborhood decision";
        needle = "deliver-delayed-vote-first";
      }
    ]
    ++ failuresFor "crates/crucible/tests/example_corpus.rs" exampleTest [
      {
        label = "built-in family test";
        needle = "fault_campaign_is_shipped_as_builtin_family";
      }
      {
        label = "fuzz replay save resume fork proof test";
        needle = "fault_campaign_fuzz_replay_save_resume_and_fork_are_proven";
      }
      {
        label = "coverage-guided operation assertion";
        needle = "UnifiedGraphOperationKind::CoverageGuidedFuzzing";
      }
      {
        label = "finding discovery path assertion";
        needle = "FindingDiscoveryPath::CoverageGuidedFuzzing";
      }
      {
        label = "violation observation assertion";
        needle = "report.violation_observations";
      }
      {
        label = "violation report assertion";
        needle = "report.violation_report.verdict().is_failed()";
      }
      {
        label = "artifact-bound replay assertion";
        needle = "report.violation_replay.artifact";
      }
      {
        label = "artifact schedule carries violation";
        needle = "fault-campaign/violation";
      }
      {
        label = "fork schedule assertion";
        needle = "report.fork.branch.schedule.len(), 1";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionRoot [
      {
        label = "session facade family name";
        needle = "FAULT_CAMPAIGN_FAMILY_NAME";
      }
      {
        label = "session facade runner";
        needle = "run_fault_campaign_example";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "built-in fuzz family enum";
        needle = "BuiltInFaultCampaign";
      }
      {
        label = "built-in family parser";
        needle = "value == crucible::FAULT_CAMPAIGN_FAMILY_NAME";
      }
      {
        label = "built-in fuzz runner";
        needle = "run_builtin_fault_campaign_fuzz";
      }
      {
        label = "local proof call";
        needle = "crucible::run_fault_campaign_example(plan.config)";
      }
      {
        label = "generic fuzz remains T-CLI-13";
        needle = "requires the exploration-engine driver over phase-6 fuzzing policies tracked by T-CLI-13";
      }
      {
        label = "built-in CLI test";
        needle = "cli_fuzz_runs_builtin_fault_campaign_family";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 fault campaign import";
        needle = "faultCampaignExample = import ./phase7-fault-campaign-example.nix";
      }
      {
        label = "phase7 fault campaign attr path";
        needle = "checks.crucible.phase7.faultCampaignExample";
      }
      {
        label = "phase7 fault campaign task id";
        needle = "taskIds = [\"T-EX-4\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 fault-campaign example check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-fault-campaign-example";
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-fault-campaign-example";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-campaign-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test example_corpus \
              fault_campaign \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-campaign-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_fuzz_runs_builtin_fault_campaign_family \
              -- --test-threads=1
            touch "$out"
          '';
        }
      ];
      meta = {
        description = "RFC0010 ${attrPath} (${builtins.concatStringsSep "," taskIds})";
      };
    }
