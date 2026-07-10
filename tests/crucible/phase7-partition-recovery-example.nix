{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.partitionRecoveryExample",
  taskIds ? ["T-EX-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  exampleDoc = builtins.readFile ../../docs/rfcs/0010-crucible/33-examples-and-workloads.md;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  exampleCorpus = builtins.readFile ../../crates/crucible/src/example_corpus.rs;
  exampleTest = builtins.readFile ../../crates/crucible/tests/example_corpus.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/33-examples-and-workloads.md" exampleDoc [
      {
        label = "T-EX-2 checked off";
        needle = "- [x] **T-EX-2**";
      }
      {
        label = "T-EX-2 completion note";
        needle = "Completed by `checks.crucible.phase7.partitionRecoveryExample`";
      }
      {
        label = "partition recovery spec remains documented";
        needle = "### A.2 Partition recovery";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "partition recovery name re-export";
        needle = "PARTITION_RECOVERY_SCENARIO_NAME";
      }
      {
        label = "partition recovery fixture re-export";
        needle = "partition_recovery_scenario";
      }
      {
        label = "partition recovery verify re-export";
        needle = "verify_partition_recovery_default_runs";
      }
    ]
    ++ failuresFor "crates/crucible/src/example_corpus.rs" exampleCorpus [
      {
        label = "partition corpus name";
        needle = "pub const PARTITION_RECOVERY_SCENARIO_NAME: &str = \"partition-recovery.scn\";";
      }
      {
        label = "built-in corpus includes partition fixture";
        needle = "partition_recovery_scenario()?";
      }
      {
        label = "partition fixture function";
        needle = "pub fn partition_recovery_scenario";
      }
      {
        label = "partition no split brain assertion";
        needle = "no-split-brain";
      }
      {
        label = "partition convergence assertion";
        needle = "converges-after-heal";
      }
      {
        label = "assertion state convergence trigger";
        needle = "Predicate::assertion_state";
      }
      {
        label = "all-of readiness graph";
        needle = "Predicate::all_of";
      }
      {
        label = "coverage readiness point";
        needle = "CodePoint::guest_address(0x4010)";
      }
      {
        label = "partition injection action";
        needle = "Action::inject_fault";
      }
      {
        label = "db0 side isolated under split tag";
        needle = "MembershipFault::Isolate";
      }
      {
        label = "relative heal timer";
        needle = "Action::arm_timer";
      }
      {
        label = "heal action";
        needle = "Action::heal_fault";
      }
      {
        label = "observable convergence frame";
        needle = "reconcile_ack raft_log_match";
      }
      {
        label = "pass waits for healed split";
        needle = "Predicate::not(Predicate::fault_active(partition_fault_tag()))";
      }
      {
        label = "single scheduler action path";
        needle = "SingleScheduler::new";
      }
      {
        label = "trigger actions applied into log";
        needle = "scheduler.apply_trigger_firings";
      }
      {
        label = "derived assertion-state events";
        needle = "fn assertion_state_event_from_outcome";
      }
      {
        label = "multi-step replay schedule";
        needle = "fn example_schedule";
      }
      {
        label = "coverage replay encoding";
        needle = "coverage-block";
      }
      {
        label = "assertion-state replay encoding";
        needle = "assertion-state-changed";
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
        label = "built-in partition corpus test";
        needle = "partition_recovery_is_shipped_as_builtin_corpus_fixture";
      }
      {
        label = "observable graph shape test";
        needle = "partition_recovery_uses_observable_trigger_graph";
      }
      {
        label = "partition round-trip test";
        needle = "partition_recovery_round_trips_as_reproducible_scenario_material";
      }
      {
        label = "partition run and verify test";
        needle = "partition_recovery_run_passes_and_verify_runs_are_byte_identical";
      }
      {
        label = "partition action assertion";
        needle = "assert_partition_injection";
      }
      {
        label = "convergence trigger assertion";
        needle = "assert_convergence_trigger_shape";
      }
      {
        label = "assertion outcome kind check";
        needle = "HostAssertionOutcomeKind::Satisfied";
      }
      {
        label = "schedule does not script assertion state";
        needle = "contains(\"assertion-state-changed\")";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "selftest includes partition corpus";
        needle = "partition-recovery.scn";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 partition import";
        needle = "partitionRecoveryExample = import ./phase7-partition-recovery-example.nix";
      }
      {
        label = "phase7 partition attr path";
        needle = "checks.crucible.phase7.partitionRecoveryExample";
      }
      {
        label = "phase7 partition task id";
        needle = "taskIds = [\"T-EX-2\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 partition-recovery example check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-partition-recovery-example";
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
          name = "run-partition-recovery-example";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-partition-recovery-example-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test example_corpus \
              partition_recovery \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-partition-recovery-example-target" \
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
            corpus=partition-recovery.scn
            run=passed
            verify_runs=byte-identical
            trigger_graph=allof-ready+timer-heal+observable-convergence
            assertions=no-split-brain,converges-after-heal
            guest_components=none
            RESULT
          '';
        }
      ];
    }
