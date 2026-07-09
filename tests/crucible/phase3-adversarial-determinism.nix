{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.gates.adversarialDeterminism",
  taskIds ? ["T-PLAN-3" "T-HARN-22"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  adversarial = builtins.readFile ../../crates/crucible-harness/src/adversarial.rs;
  gateTest = builtins.readFile ../../crates/crucible-harness/tests/gate_adversarial_determinism.rs;
  engineGateTest = builtins.readFile ../../crates/crucible/tests/gate_adversarial_determinism.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

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
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-22 checked off";
        needle = "- [x] **T-HARN-22**";
      }
      {
        label = "T-HARN-22 completion note";
        needle = "Completed by `checks.crucible.phase3.gates.adversarialDeterminism`";
      }
      {
        label = "modeled hostile-condition phase table scope";
        needle = "phase3  gate:adversarial-determinism       (modeled hostile-condition matrix)";
      }
      {
        label = "real VM/fleet scope remains packaging work";
        needle = "real AOS\n  VM/fleet checks remain owned by the packaging tasks";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/adversarial.rs" adversarial [
      {
        label = "scenario type";
        needle = "pub struct AdversarialScenario";
      }
      {
        label = "scenario operation type";
        needle = "pub enum AdversarialScenarioOperation";
      }
      {
        label = "gate report type";
        needle = "pub struct AdversarialGateReport";
      }
      {
        label = "gate error type";
        needle = "pub enum AdversarialGateError";
      }
      {
        label = "representative corpus";
        needle = "pub fn representative_adversarial_corpus()";
      }
      {
        label = "gate runner";
        needle = "pub fn run_adversarial_determinism_gate";
      }
      {
        label = "custom observer gate runner";
        needle = "pub fn run_adversarial_determinism_gate_with_observer";
      }
      {
        label = "post-profile observation input";
        needle = "pub struct AdversarialObservation";
      }
      {
        label = "default canonical observation";
        needle = "fn canonical_adversarial_observation";
      }
      {
        label = "shared hostile matrix";
        needle = "canonical_host_adversary_matrix";
      }
      {
        label = "shared producer/consumer runner";
        needle = "run_profiled_producer_consumer_tasks";
      }
      {
        label = "host I/O modeled operation";
        needle = "AdversarialScenarioOperation::HostIo";
      }
      {
        label = "host I/O canonical record";
        needle = "operation.host-io";
      }
      {
        label = "canonical log material";
        needle = "canonical_log";
      }
      {
        label = "final fingerprint material";
        needle = "final_fingerprint";
      }
      {
        label = "stable digest";
        needle = "fn stable_digest";
      }
      {
        label = "adversarial comparison";
        needle = "compare_adversarial_runs(&runs)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_adversarial_determinism.rs" gateTest [
      {
        label = "implemented success gate test";
        needle = "gate_adversarial_determinism_compares_canonical_bytes_under_hostile_profiles";
      }
      {
        label = "profile matrix use";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "representative corpus use";
        needle = "representative_adversarial_corpus()";
      }
      {
        label = "gate runner use";
        needle = "run_adversarial_determinism_gate(&corpus, profiles)";
      }
      {
        label = "profile-dependent log negative control";
        needle = "gate_adversarial_determinism_rejects_profile_dependent_logs";
      }
      {
        label = "gate runner profile-leak negative control";
        needle = "gate_adversarial_determinism_rejects_profile_dependent_observer_output";
      }
      {
        label = "profile-dependent fingerprint negative control";
        needle = "gate_adversarial_determinism_rejects_profile_dependent_fingerprints";
      }
      {
        label = "empty input negative control";
        needle = "gate_adversarial_determinism_rejects_empty_inputs";
      }
      {
        label = "canonical log equality assertion";
        needle = "assert_eq!(run.canonical_log, baseline.canonical_log)";
      }
      {
        label = "fingerprint equality assertion";
        needle = "assert_eq!(run.final_fingerprint, baseline.final_fingerprint)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_adversarial_determinism.rs" engineGateTest [
      {
        label = "engine adversarial gate target";
        needle = "Checks `gate:adversarial-determinism` (the Phase-3 exit gate) on the REAL";
      }
      {
        label = "real scheduler coverage";
        needle = "SingleScheduler";
      }
      {
        label = "host adversary matrix coverage";
        needle = "canonical_host_adversary_matrix()";
      }
      {
        label = "stable corpus name";
        needle = "gate-adversarial-determinism-corpus";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/tests/gate_adversarial_determinism.rs" gateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "stale phase table 2-VM scope";
        needle = "gate:adversarial-determinism       (2-VM hostile-condition matrix)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "adversarial gate catalog implemented";
        needle = "name: \"gate:adversarial-determinism\",\n        phase: GatePhase::Phase3,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "adversarial target implemented";
        needle = "gate: \"gate:adversarial-determinism\",\n        package: \"crucible\",\n        test_target: \"gate_adversarial_determinism\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "adversarial implemented status assertion";
        needle = "find_gate(\"gate:adversarial-determinism\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "adversarial target mapping implemented";
        needle = "gate = \"gate:adversarial-determinism\";\n      package = \"crucible\";\n      testTarget = \"gate_adversarial_determinism\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "placeholder count updated";
        needle = "placeholder_targets=2";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 imports adversarial determinism check";
        needle = "adversarialDeterminism = import ./phase3-adversarial-determinism.nix";
      }
      {
        label = "phase3 adversarial attr path";
        needle = "attrPath = \"checks.crucible.phase3.gates.adversarialDeterminism\"";
      }
      {
        label = "phase3 adversarial task id";
        needle = "\"T-HARN-22\"";
      }
    ]
    ++ forbiddenFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "adversarial red gate";
        needle = "adversarialDeterminism = redGate";
      }
      {
        label = "adversarial pending reason";
        needle = "adversarial determinism gate is intentionally pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 adversarial-determinism gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-adversarial-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ] ++ dependencies;

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
          name = "run-adversarial-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-determinism-target" \
              -p crucible-harness \
              --test gate_adversarial_determinism \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-adversarial-determinism-target" \
              -p crucible \
              --test gate_adversarial_determinism \
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
            gate=gate:adversarial-determinism
            tasks=${taskList}
            rust_tests=crucible-harness::gate_adversarial_determinism,crucible::gate_adversarial_determinism
            hostile_profiles=quiet-single-core,loaded-single-core,reordered-two-core,loaded-many-core
            hostile_dimensions=task-order,logical-affinity,load-yield,worker-count,producer-consumer-skew,host-io
            representative_scenarios=2
            byte_identical_canonical_logs=true
            byte_identical_final_fingerprints=true
            profile_dependent_negative_control=true
            RESULT
          '';
        }
      ];
    }
