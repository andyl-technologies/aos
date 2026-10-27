{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.assertionDeterminismNonPerturbation",
  taskIds ? ["T-ASRT-13"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  triggerAssertions = builtins.readFile ../../crates/crucible/crucible-engine/src/trigger/assertions.rs;
  determinismTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-engine/tests/assertion_determinism_nonperturbation.rs;
  };
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
  defaultChecks = builtins.readFile ./default.nix;
  assertionEngineBlock =
    builtins.elemAt (
      lib.splitString "fn push_observed_state_facts" (
        builtins.elemAt (lib.splitString "pub struct OfflineAssertionChecker" triggerAssertions) 1
      )
    )
    0;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-13 completion note";
        needle = "Completed by `checks.crucible.phase4.assertionDeterminismNonPerturbation`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/trigger.rs" trigger [
      {
        label = "read-only observed-state slices";
        needle = "observable_events: &'log [ObservableEvent]";
      }
      {
        label = "read-only ordering facts";
        needle = "ordering_facts: &'log [ObservedOrderingFact]";
      }
      {
        label = "typed fault evidence handled without exposing internal fault state";
        needle = "SchedulerEventLogPayload::FaultObservation(_)";
      }
      {
        label = "stable outcome sort";
        needle = "sort_host_assertion_outcomes";
      }
      {
        label = "deterministic guest marker insertion";
        needle = "binary_search_by";
      }
      {
        label = "deterministic deadline collection";
        needle = "BTreeSet::new";
      }
      {
        label = "deterministic leaf cache";
        needle = "BTreeMap<HostConditionLeafKey, bool>";
      }
      {
        label = "offline shared evaluator";
        needle = "HostAssertionEvaluator::new(properties)";
      }
      {
        label = "unified host guest outcome merge";
        needle = ".chain(";
      }
      {
        label = "host harness lint API";
        needle = "pub fn lint_host_assertion_harness_source";
      }
      {
        label = "host assertion predicate API";
        needle = "pub trait HostAssertionPredicate";
      }
      {
        label = "linted host assertion oracle";
        needle = "pub struct LintedHostAssertionOracle";
      }
      {
        label = "host assertion predicate answers from accumulator state";
        needle = "fn leaf_is_true(&self, leaf: NamedLeaf<'_>, state: &Self::State) -> bool;";
      }
      {
        label = "sealed host assertion oracle module";
        needle = "mod host_assertion_oracle_sealed";
      }
      {
        label = "sealed host assertion oracle trait";
        needle = "pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed";
      }
      {
        label = "closure predicate blanket impl";
        needle = "F: for<'leaf, 'batch> Fn(NamedLeaf<'leaf>, &ObservedBatch<'batch>) -> bool";
      }
      {
        label = "host harness lint error";
        needle = "pub struct HostAssertionHarnessLintError";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/tests/assertion_determinism_nonperturbation.rs" determinismTest [
      {
        label = "online offline determinism test";
        needle = "merged_host_and_guest_outcomes_are_bit_identical_online_offline_and_repeated";
      }
      {
        label = "backend fingerprint neutrality test";
        needle = "assertion_evaluation_is_side_effect_free_for_backend_fingerprints";
      }
      {
        label = "static nondeterminism guard test";
        needle = "assertion_evaluator_rejects_banned_nondeterminism_and_live_state_access";
      }
      {
        label = "host harness lint rejection test";
        needle = "host_assertion_harness_lint_rejects_banned_predicate_operations";
      }
      {
        label = "host harness lint acceptance test";
        needle = "host_assertion_harness_lint_accepts_pure_accumulator_predicates";
      }
      {
        label = "stable merge order assertion";
        needle = "host and guest marker outcomes must merge by stable id";
      }
      {
        label = "fingerprint neutrality assertion";
        needle = "assertion evaluation must not perturb backend fingerprint state";
      }
      {
        label = "recorded log input";
        needle = "RecordedAssertionLog::from_segments";
      }
      {
        label = "test-double feature witness";
        needle = "#[cfg(feature = \"test-double\")]";
      }
      {
        label = "host harness lint API call";
        needle = "lint_host_assertion_harness_source";
      }
      {
        label = "custom predicates require lint wrapper";
        needle = "LintedHostAssertionOracle";
      }
      {
        label = "test custom predicates use unchecked debug helper";
        needle = "unchecked_host_assertion_oracle_for_test";
      }
      {
        label = "deterministic oracle uses predicate trait";
        needle = "impl HostAssertionPredicate for DeterministicOracle";
      }
      {
        label = "direct entropy lint witness";
        needle = "getrandom";
      }
      {
        label = "os rng lint witness";
        needle = "OsRng";
      }
      {
        label = "randomized hasher lint witness";
        needle = "DefaultHasher";
      }
      {
        label = "random state lint witness";
        needle = "RandomState";
      }
      {
        label = "entropy seed lint witness";
        needle = "from_entropy";
      }
      {
        label = "grouped filesystem import lint witness";
        needle = "std::{fs";
      }
      {
        label = "grouped process import lint witness";
        needle = "process::Command";
      }
      {
        label = "environment lint witness";
        needle = "std::env";
      }
      {
        label = "network lint witness";
        needle = "std::net";
      }
      {
        label = "host io lint witness";
        needle = "std::io";
      }
      {
        label = "shared mutable state lint witness";
        needle = "Mutex";
      }
      {
        label = "interior mutability lint witness";
        needle = "RefCell";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 assertion determinism import";
        needle = "assertionDeterminismNonPerturbation = import ./phase4-assertion-determinism-nonperturbation.nix";
      }
      {
        label = "phase4 assertion determinism attr path";
        needle = "attrPath = \"checks.crucible.phase4.assertionDeterminismNonPerturbation\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/src/trigger.rs" assertionEngineBlock [
      {
        label = "unordered HashMap";
        needle = "HashMap";
      }
      {
        label = "unordered HashSet";
        needle = "HashSet";
      }
      {
        label = "wall clock SystemTime";
        needle = "SystemTime";
      }
      {
        label = "wall clock Instant";
        needle = "Instant";
      }
      {
        label = "std time access";
        needle = "std::time";
      }
      {
        label = "thread rng";
        needle = "thread_rng";
      }
      {
        label = "direct entropy";
        needle = "getrandom";
      }
      {
        label = "os rng";
        needle = "OsRng";
      }
      {
        label = "randomized hasher";
        needle = "DefaultHasher";
      }
      {
        label = "random state";
        needle = "RandomState";
      }
      {
        label = "entropy seed";
        needle = "from_entropy";
      }
      {
        label = "rand crate direct use";
        needle = "rand::";
      }
      {
        label = "environment access";
        needle = "std::env";
      }
      {
        label = "thread access";
        needle = "std::thread";
      }
      {
        label = "filesystem access";
        needle = "std::fs";
      }
      {
        label = "process access";
        needle = "std::process";
      }
      {
        label = "process command access";
        needle = "process::Command";
      }
      {
        label = "network access";
        needle = "std::net";
      }
      {
        label = "host io access";
        needle = "std::io";
      }
      {
        label = "file open access";
        needle = "OpenOptions";
      }
      {
        label = "host scheduling select";
        needle = "tokio::select";
      }
      {
        label = "host scheduling select macro";
        needle = "select!";
      }
      {
        label = "shared mutable atomic state";
        needle = "Atomic";
      }
      {
        label = "shared mutable lock state";
        needle = "Mutex";
      }
      {
        label = "interior mutability";
        needle = "RefCell";
      }
      {
        label = "unsafe code";
        needle = "unsafe";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/src/trigger.rs" trigger [
      {
        label = "raw closure host assertion oracle";
        needle = "impl<F> HostAssertionOracle for F";
      }
      {
        label = "public mismatched source predicate constructor";
        needle = "pub fn from_source";
      }
      {
        label = "public lint proof wrapper constructor";
        needle = "pub fn new(oracle";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/tests/assertion_determinism_nonperturbation.rs" determinismTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "raw deterministic oracle implementation";
        needle = "impl HostAssertionOracle for DeterministicOracle";
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
  then throw "crucible phase4 assertion-determinism-nonperturbation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase4-assertion-determinism-nonperturbation";

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-assertion-determinism-nonperturbation";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              --features test-double \
              -p crucible-engine \
              --test assertion_determinism_nonperturbation \
              --test property_fingerprint_neutrality \
              --test assertion_evaluation_order \
              --test offline_assertion_checker \
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
            assertion_determinism_nonperturbation=true
            RESULT
          '';
        }
      ];
    }
