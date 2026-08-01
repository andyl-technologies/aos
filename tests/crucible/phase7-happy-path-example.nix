{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.happyPathExample",
  taskIds ? ["T-EX-1"],
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
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  exampleTest = builtins.readFile ../../crates/crucible/tests/example_corpus.rs;
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-1 completion note";
        needle = "Completed by `checks.crucible.phase7.happyPathExample`";
      }
      {
        label = "EX-1 zero guest components";
        needle = "zero guest-side components";
      }
      {
        label = "EX-2 byte-identical verify";
        needle = "MUST produce byte-identical canonical event logs and fingerprint";
      }
      {
        label = "EX-3 built-in corpus";
        needle = "MUST be shipped as a built-in scenario corpus";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "example corpus module";
        needle = "pub mod example_corpus;";
      }
      {
        label = "happy path name re-export";
        needle = "HAPPY_PATH_SCENARIO_NAME";
      }
      {
        label = "built-in corpus re-export";
        needle = "built_in_example_corpus";
      }
      {
        label = "happy path fixture re-export";
        needle = "happy_path_scenario";
      }
      {
        label = "run helper re-export";
        needle = "run_example_scenario";
      }
      {
        label = "verify helper re-export";
        needle = "verify_example_scenario_runs";
      }
    ]
    ++ failuresFor "crates/crucible/src/example_corpus.rs" exampleCorpus [
      {
        label = "corpus version";
        needle = "pub const BUILT_IN_EXAMPLE_CORPUS_VERSION";
      }
      {
        label = "happy-path corpus name";
        needle = "pub const HAPPY_PATH_SCENARIO_NAME: &str = \"happy-path.scn\";";
      }
      {
        label = "zero guest components invariant";
        needle = "pub const EXAMPLE_CORPUS_REQUIRES_GUEST_COMPONENTS: bool = false;";
      }
      {
        label = "white-box not required invariant";
        needle = "pub const EXAMPLE_CORPUS_WHITE_BOX_REQUIRED: bool = false;";
      }
      {
        label = "built-in corpus function";
        needle = "pub fn built_in_example_corpus";
      }
      {
        label = "happy-path fixture function";
        needle = "pub fn happy_path_scenario";
      }
      {
        label = "run helper";
        needle = "pub fn run_example_scenario";
      }
      {
        label = "verify helper";
        needle = "pub fn verify_example_scenario_runs";
      }
      {
        label = "default happy-path verify";
        needle = "pub fn verify_happy_path_default_runs";
      }
      {
        label = "HTTP server workload";
        needle = "GuestWorkloadBinary::Httpd";
      }
      {
        label = "HTTP client workload";
        needle = "GuestWorkloadBinary::ClientLoop";
      }
      {
        label = "target scalar";
        needle = "GuestWorkloadParameterKey::Target";
      }
      {
        label = "count scalar";
        needle = "GuestWorkloadParameterKey::Count";
      }
      {
        label = "console readiness";
        needle = "ReadyPoint::ConsoleMarker";
      }
      {
        label = "network match assertion";
        needle = "Predicate::network_match";
      }
      {
        label = "quiescence pass";
        needle = "Predicate::quiescent()";
      }
      {
        label = "pass action";
        needle = "Action::pass()";
      }
      {
        label = "run passes outcome";
        needle = "ExampleScenarioRunOutcome::Passed";
      }
      {
        label = "black-box assertion oracle";
        needle = "BlackBoxHostOracle";
      }
      {
        label = "host assertion grading";
        needle = "HostAssertionEvaluator::new";
      }
      {
        label = "assertion report";
        needle = "assertion_report";
      }
      {
        label = "assertion failure error";
        needle = "AssertionsFailed";
      }
      {
        label = "schedule-backed replay script";
        needle = "fn example_script_from_schedule";
      }
      {
        label = "schedule carries observations";
        needle = "fn happy_path_schedule";
      }
      {
        label = "schedule override records";
        needle = "Decision::Override";
      }
      {
        label = "invalid replay schedule error";
        needle = "ReplayScheduleInvalid";
      }
      {
        label = "reproduction artifact capture";
        needle = "ReproductionArtifact::capture";
      }
      {
        label = "artifact-only replay helper call";
        needle = "replay_example_scenario_artifact(&fixture.name, &reproduction)?";
      }
      {
        label = "reproduction artifact replay";
        needle = "reproduction.replay()?";
      }
      {
        label = "replay divergence error";
        needle = "ReplayDiverged";
      }
      {
        label = "replayed event log";
        needle = "replayed_canonical_event_log";
      }
      {
        label = "replayed fingerprint";
        needle = "replayed_fingerprint_stream";
      }
      {
        label = "byte-identical log comparison";
        needle = "candidate.canonical_event_log != reference.canonical_event_log";
      }
      {
        label = "byte-identical fingerprint comparison";
        needle = "candidate.fingerprint_stream != reference.fingerprint_stream";
      }
      {
        label = "byte-identical replay log comparison";
        needle = "candidate.replayed_canonical_event_log != reference.replayed_canonical_event_log";
      }
      {
        label = "byte-identical replay fingerprint comparison";
        needle = "candidate.replayed_fingerprint_stream != reference.replayed_fingerprint_stream";
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
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "public event-log observable append";
        needle = "pub fn append_observable_events";
      }
      {
        label = "public event-log boundary append";
        needle = "pub fn append_evaluation_boundary";
      }
    ]
    ++ failuresFor "crates/crucible/tests/example_corpus.rs" exampleTest [
      {
        label = "built-in corpus test";
        needle = "happy_path_is_shipped_as_builtin_corpus_fixture";
      }
      {
        label = "black-box authoring test";
        needle = "happy_path_authoring_uses_only_black_box_guest_observables";
      }
      {
        label = "scenario round-trip test";
        needle = "happy_path_round_trips_as_reproducible_scenario_material";
      }
      {
        label = "run and verify test";
        needle = "happy_path_run_passes_and_verify_runs_are_byte_identical";
      }
      {
        label = "zero run rejection test";
        needle = "verify_requires_at_least_one_run";
      }
      {
        label = "replay assertion";
        needle = "run.reproduction.replay()?";
      }
      {
        label = "schedule-backed reproduction";
        needle = "run.reproduction.schedule().decisions().len()";
      }
      {
        label = "assertion report verdict";
        needle = "run.assertion_report.verdict().is_failed()";
      }
      {
        label = "assertion outcome coverage";
        needle = "all-requests-succeed";
      }
      {
        label = "replayed log equality";
        needle = "run.replayed_canonical_event_log";
      }
      {
        # Drift: the corpus panic message says "example corpus", not
        # "happy path" — same D-31 invariant (no guest markers required).
        label = "guest marker rejection";
        needle = "example corpus must not require guest markers";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI depends on the session facade that re-exports the corpus";
        needle = "crucible-session = { path = \"../crucible-session\" }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "selftest dispatch";
        needle = "Commands::Selftest(_) =>";
      }
      {
        label = "selftest runner";
        needle = "fn run_selftest";
      }
      {
        label = "selftest corpus load";
        needle = "crucible::built_in_example_corpus()";
      }
      {
        label = "selftest corpus verification";
        needle = "crucible::verify_example_scenario_runs";
      }
      {
        label = "selftest CLI test";
        needle = "cli_selftest_runs_builtin_example_corpus";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 happy-path import";
        needle = "happyPathExample = import ./phase7-happy-path-example.nix";
      }
      {
        label = "phase7 happy-path attr path";
        needle = "checks.crucible.phase7.happyPathExample";
      }
      {
        label = "phase7 happy-path task id";
        needle = "taskIds = [\"T-EX-1\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 happy-path example check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-happy-path-example";
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
          name = "run-happy-path-example";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-happy-path-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test example_corpus \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-happy-path-example-target" \
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
            corpus=happy-path.scn
            run=passed
            verify_runs=byte-identical
            guest_components=none
            RESULT
          '';
        }
      ];
    }
