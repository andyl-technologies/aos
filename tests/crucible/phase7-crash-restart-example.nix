{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crashRestartExample",
  taskIds ? ["T-EX-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  exampleDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  exampleCorpus = builtins.readFile ../../crates/crucible/src/example_corpus.rs;
  exampleTest = builtins.readFile ../../crates/crucible/tests/example_corpus.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-3 completion note";
        needle = "Completed by `checks.crucible.phase7.crashRestartExample`";
      }
      {
        label = "crash restart implementation note";
        needle = "Implementation note (T-EX-3)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "crash restart name re-export";
        needle = "CRASH_RESTART_SCENARIO_NAME";
      }
      {
        label = "crash restart fixture re-export";
        needle = "crash_restart_scenario";
      }
      {
        label = "crash restart verify re-export";
        needle = "verify_crash_restart_default_runs";
      }
    ]
    ++ failuresFor "crates/crucible/src/example_corpus.rs" exampleCorpus [
      {
        label = "crash restart corpus name";
        needle = "pub const CRASH_RESTART_SCENARIO_NAME: &str = \"crash-restart.scn\";";
      }
      {
        label = "built-in corpus includes crash fixture";
        needle = "crash_restart_scenario()?";
      }
      {
        label = "crash fixture function";
        needle = "pub fn crash_restart_scenario";
      }
      {
        label = "default verifier";
        needle = "verify_crash_restart_default_runs";
      }
      {
        label = "data-not-lost assertion";
        needle = "data-not-lost";
      }
      {
        label = "data-not-lost is safety";
        needle = "Property::Always";
      }
      {
        label = "data loss evidence forbidden";
        needle = "data_lost=true";
      }
      {
        label = "reconverges assertion";
        needle = "reconverges";
      }
      {
        label = "WAL write trigger";
        needle = "IoEventKind::BlockWrite";
      }
      {
        label = "crash fault action";
        needle = "MembershipFault::Crash";
      }
      {
        label = "FromReadyPoint policy";
        needle = "RestartPolicy::FromReadyPoint";
      }
      {
        label = "after anchored restart";
        needle = "Predicate::after";
      }
      {
        label = "start node choreography";
        needle = "Action::start_node";
      }
      {
        label = "derived lifecycle events";
        needle = "fn trigger_lifecycle_event";
      }
      {
        label = "scheduler crash applications recorded";
        needle = "scheduler.node_crash_applications().to_vec()";
      }
      {
        label = "scheduler restart applications recorded";
        needle = "scheduler.node_restart_applications().to_vec()";
      }
      {
        label = "scheduler topology applications recorded";
        needle = "scheduler.topology_change_applications().to_vec()";
      }
      {
        label = "queued topology changes applied";
        needle = "apply_queued_topology_changes_at_boundary";
      }
      {
        label = "real scheduler quiescence";
        needle = "scheduler.quiescence()?";
      }
      {
        label = "idle scheduler nodes";
        needle = "SchedulerNodeActivity::Idle";
      }
      {
        label = "scheduler nodes from world";
        needle = "fn example_scheduler_nodes";
      }
      {
        label = "scheduler topology from world";
        needle = "fn example_scheduler_edges";
      }
      {
        label = "effective topology wired";
        needle = "with_effective_topology_edges";
      }
      {
        label = "I/O replay encoding";
        needle = "io-completion";
      }
      {
        label = "WAL payload evidence";
        needle = "region=wal";
      }
      {
        label = "observable convergence frame";
        needle = "committed_write_survived=true raft_log_match";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/example_corpus.rs" exampleCorpus [
      {
        label = "guest-marker dependency";
        needle = "Predicate::guest_marker";
      }
      {
        label = "white-box enabled dependency";
        needle = "WhiteBoxPolicy::Enabled";
      }
      {
        label = "reserved unsupported workload key";
        needle = "crucible.workload=replicated-store";
      }
    ]
    ++ failuresFor "crates/crucible/tests/example_corpus.rs" exampleTest [
      {
        label = "built-in crash corpus test";
        needle = "crash_restart_is_shipped_as_builtin_corpus_fixture";
      }
      {
        label = "observable graph shape test";
        needle = "crash_restart_uses_observable_trigger_graph";
      }
      {
        label = "crash round-trip test";
        needle = "crash_restart_round_trips_as_reproducible_scenario_material";
      }
      {
        label = "crash run and verify test";
        needle = "crash_restart_run_passes_and_verify_runs_are_byte_identical";
      }
      {
        label = "crash trigger assertion";
        needle = "assert_crash_after_commit_trigger_shape";
      }
      {
        label = "reconvergence trigger assertion";
        needle = "assert_crash_reconvergence_trigger_shape";
      }
      {
        label = "liveness outcome kind check";
        needle = "HostAssertionOutcomeKind::Satisfied";
      }
      {
        label = "safety outcome kind check";
        needle = "HostAssertionOutcomeKind::Passed";
      }
      {
        label = "scheduler crash application test";
        needle = "scheduler_crash_applications";
      }
      {
        label = "scheduler restart application test";
        needle = "scheduler_restart_applications";
      }
      {
        label = "scheduler topology application test";
        needle = "scheduler_topology_change_applications";
      }
      {
        label = "edge removal test";
        needle = "removed_edges.len(), 4";
      }
      {
        label = "edge restoration test";
        needle = "restored_edges";
      }
      {
        label = "data-not-lost safety test";
        needle = "data_lost=true";
      }
      {
        label = "WAL payload test";
        needle = "region=wal";
      }
      {
        label = "schedule carries I/O completion";
        needle = "contains(\"io-completion\")";
      }
      {
        label = "schedule does not script assertion state";
        needle = "contains(\"assertion-state-changed\")";
      }
      {
        label = "schedule does not script crash state";
        needle = "contains(\"node-state|30|db-1|crashed\")";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "selftest includes crash corpus";
        needle = "crash-restart.scn";
      }
      {
        label = "selftest verifies three examples";
        needle = "assert_eq!(report.verified.len(), 3)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 crash import";
        needle = "crashRestartExample = import ./phase7-crash-restart-example.nix";
      }
      {
        label = "phase7 crash attr path";
        needle = "checks.crucible.phase7.crashRestartExample";
      }
      {
        label = "phase7 crash task id";
        needle = "taskIds = [\"T-EX-3\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 crash-restart example check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crash-restart-example";
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
          name = "run-crash-restart-example";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-crash-restart-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test example_corpus \
              crash_restart \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-crash-restart-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_selftest_runs_builtin_example_corpus \
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
            corpus=crash-restart.scn
            run=passed
            verify_runs=byte-identical
            trigger_graph=wal-write-crash+after-restart+observable-convergence
            assertions=data-not-lost,reconverges
            guest_components=none
            RESULT
          '';
        }
      ];
    }
