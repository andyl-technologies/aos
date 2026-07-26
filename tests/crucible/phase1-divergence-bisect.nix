{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.divergenceBisect",
  taskIds ? ["T-HARN-9" "T-HARN-10" "T-HARN-13" "T-DET-20" "T-EXEC-12"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  divergenceHarness = builtins.readFile ../../crates/crucible-harness/src/divergence.rs;
  divergenceTypes = builtins.readFile ../../crates/crucible-harness/src/divergence/types.rs;
  replayOracleHarness = builtins.readFile ../../crates/crucible-harness/src/replay_oracle.rs;
  divergenceGate = builtins.readFile ../../crates/crucible-harness/tests/gate_divergence_bisect.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  executionModel = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;

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
    failuresFor "crates/crucible-harness/src/divergence/types.rs" divergenceTypes [
      {
        label = "full bisection report";
        needle = "pub struct DivergenceBisectionReport";
      }
      {
        label = "state dump type";
        needle = "pub struct DivergenceStateDump";
      }
      {
        label = "state diff type";
        needle = "pub struct DivergenceStateDiff";
      }
      {
        label = "schedule decision trace type";
        needle = "pub struct DecisionTraceEntry";
      }
      {
        label = "exact first differing icount";
        needle = "pub first_different_icount: u64";
      }
      {
        label = "first differing decision field";
        needle = "pub first_different_decision: Option<DecisionTraceMismatch>";
      }
      {
        label = "last matching both-sides dump";
        needle = "pub last_matching_state: Option<DivergenceStatePair>";
      }
      {
        label = "first differing state diff";
        needle = "pub first_different_state_diff: DivergenceStateDiff";
      }
      {
        label = "matching streams rejected";
        needle = "MatchingStreams";
      }
      {
        label = "definition mismatch rejected";
        needle = "DefinitionMismatch";
      }
      {
        label = "final mismatch rejected";
        needle = "FinalFingerprintMismatch";
      }
      {
        label = "refined bisection result";
        needle = "pub struct IcountBisection";
      }
      {
        label = "malformed state dump error";
        needle = "MalformedStateDump";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/divergence.rs" divergenceHarness [
      {
        label = "types submodule";
        needle = "mod types;";
      }
      {
        label = "public type re-exports";
        needle = "pub use types::{";
      }
      {
        label = "decision mismatch localization";
        needle = "pub fn locate_first_decision_mismatch";
      }
      {
        label = "coarse-plus-fine bisection driver";
        needle = "pub fn bisect_diverging_runs";
      }
      {
        label = "validated bisection window";
        needle = "pub fn bisect_icount_window";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/replay_oracle.rs" replayOracleHarness [
      {
        label = "replay-oracle localized mismatch type";
        needle = "pub struct ReplayOracleLocalizedMismatch";
      }
      {
        label = "replay-oracle divergence inputs";
        needle = "pub struct ReplayOracleDivergenceInputs";
      }
      {
        label = "replay-oracle search divergence materialization";
        needle = "pub struct ReplayOracleSearchDivergenceMaterialization";
      }
      {
        label = "replay-oracle localization error";
        needle = "pub enum ReplayOracleDivergenceError";
      }
      {
        label = "replay-oracle search bisection error";
        needle = "pub enum ReplayOracleSearchBisectionError";
      }
      {
        label = "replay-oracle search localization failure payload";
        needle = "pub struct ReplayOracleSearchLocalizationFailure";
      }
      {
        label = "oracle mismatch localizer";
        needle = "pub fn localize_replay_oracle_mismatch";
      }
      {
        label = "sampled oracle bisection check";
        needle = "pub fn check_sampled_search_replay_oracle_with_bisection";
      }
      {
        label = "oracle mismatch uses divergence bisection";
        needle = "bisect_diverging_runs(";
      }
      {
        label = "oracle matching streams rejected";
        needle = "Self::Divergence";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_divergence_bisect.rs" divergenceGate [
      {
        label = "seeded exact localization test";
        needle = "gate_divergence_bisect_localizes_seeded_fault_to_exact_node_and_icount";
      }
      {
        label = "deterministic rerun test";
        needle = "gate_divergence_bisect_is_deterministic_for_same_artifacts";
      }
      {
        label = "first schedule decision test";
        needle = "gate_divergence_bisect_reports_first_schedule_decision";
      }
      {
        label = "schedule length mismatch test";
        needle = "gate_divergence_bisect_reports_schedule_length_mismatch";
      }
      {
        label = "no silent repair test";
        needle = "gate_divergence_bisect_rejects_matching_streams_without_repair";
      }
      {
        label = "refined last matching dump";
        needle = "assert_eq!(last_matching.left.icount, 16);";
      }
      {
        label = "initial divergence coverage";
        needle = "gate_divergence_bisect_handles_first_sample_divergence_at_zero";
      }
      {
        label = "invalid probe window coverage";
        needle = "gate_divergence_bisect_rejects_invalid_probe_windows";
      }
      {
        label = "final-only fingerprint mismatch rejection";
        needle = "gate_divergence_bisect_rejects_final_only_fingerprint_mismatch";
      }
      {
        label = "canonical decision byte comparison";
        needle = "gate_divergence_bisect_compares_decisions_by_canonical_bytes";
      }
      {
        label = "exact first differing decision index";
        needle = "assert_eq!(decision.index, 2);";
      }
      {
        label = "exact first differing instruction icount";
        needle = "assert_eq!(report.first_different_icount, SEEDED_DIVERGENCE_ICOUNT);";
      }
      {
        label = "malformed state dump rejection";
        needle = "gate_divergence_bisect_rejects_malformed_state_dumps";
      }
      {
        label = "replay-oracle mismatch localization test";
        needle = "gate_divergence_bisect_localizes_replay_oracle_mismatch";
      }
      {
        label = "replay-oracle no-repair rejection test";
        needle = "gate_divergence_bisect_rejects_oracle_mismatch_without_divergent_streams";
      }
      {
        label = "known seeded divergence icount";
        needle = "const SEEDED_DIVERGENCE_ICOUNT: u64 = 17;";
      }
      {
        label = "both-sides state dump";
        needle = "fn state_dump(side: DivergenceSide, icount: u64) -> DivergenceStateDump";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/tests/gate_divergence_bisect.rs" divergenceGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-10";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented divergence-bisect target";
        needle = "gate: \"gate:divergence-bisect\",\n        package: \"crucible-harness\",\n        test_target: \"gate_divergence_bisect\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented divergence-bisect catalog status";
        needle = "name: \"gate:divergence-bisect\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible-harness\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "divergence-bisect implemented status assertion";
        needle = "find_gate(\"gate:divergence-bisect\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented divergence-bisect mapping target";
        needle = "gate = \"gate:divergence-bisect\";\n      package = \"crucible-harness\";\n      testTarget = \"gate_divergence_bisect\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=0";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes divergence-bisect gate";
        needle = "divergenceBisect = import ./phase1-divergence-bisect.nix";
      }
      {
        label = "phase1 divergence-bisect attr path";
        needle = "attrPath = \"checks.crucible.phase1.gates.divergenceBisect\"";
      }
      {
        label = "phase1 divergence-bisect lists T-HARN-9";
        needle = "\"T-HARN-9\"";
      }
      {
        label = "phase1 divergence-bisect lists T-HARN-10";
        needle = "\"T-HARN-10\"";
      }
      {
        label = "phase1 divergence-bisect lists T-HARN-13";
        needle = "\"T-HARN-13\"";
      }
      {
        label = "phase1 divergence-bisect lists T-DET-20";
        needle = "\"T-DET-20\"";
      }
      {
        label = "phase1 divergence-bisect lists T-EXEC-12";
        needle = "\"T-EXEC-12\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-9 checklist complete";
        needle = "- [x] **T-HARN-9**";
      }
      {
        label = "T-HARN-10 checklist complete";
        needle = "- [x] **T-HARN-10**";
      }
      {
        label = "T-HARN-13 checklist complete";
        needle = "- [x] **T-HARN-13**";
      }
      {
        label = "T-HARN-13 completion names bisection checker";
        needle = "`check_sampled_search_replay_oracle_with_bisection`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-20 checklist complete";
        needle = "- [x] **T-DET-20**";
      }
      {
        label = "DET-39 requires first differing decision";
        needle = "first differing decision";
      }
      {
        label = "DET-39 forbids repair and retry";
        needle = "be smoothed over, tolerated, or retried";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" executionModel [
      {
        label = "T-EXEC-12 checklist complete";
        needle = "- [x] **T-EXEC-12**";
      }
      {
        label = "T-EXEC-12 completion note names strict replay-oracle path";
        needle = "strict sampled\n    replay-oracle path";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 divergence-bisect gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-divergence-bisect";
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
          name = "run-divergence-bisect";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-divergence-bisect-target" \
              -p crucible-harness \
              --test gate_divergence_bisect \
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
            gate=gate:divergence-bisect
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_test=crucible-harness::gate_divergence_bisect
            localization=coarse-fingerprint-plus-exact-icount-bisection
            oracle_failure_localization=fat-thin-divergence-bisection
            replay_oracle_search_bisection=sampled-mismatch-localized
            first_different_decision=canonical-schedule-bytes
            first_different_instruction=exact-icount
            no_repair_or_retry=true
            corpus=seeded-known-divergence
            RESULT
          '';
        }
      ];
    }
