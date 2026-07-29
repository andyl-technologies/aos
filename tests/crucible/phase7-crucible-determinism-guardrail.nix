{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleDeterminismGuardrail",
  taskIds ? ["T-DCE-7"],
  dependencies ? [],
}: let
  dceDoc = builtins.readFile ../../docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md;
  harnessLintMainRust = builtins.readFile ../../crates/crucible-harness/tests/harness_lint.rs;
  harnessLintCommonRust = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/common.rs;
  harnessLintScanRust = builtins.readFile ../../crates/crucible-harness/tests/support/harness_lint/scan.rs;
  phase1HarnessLint = builtins.readFile ./phase1-harness-lint.nix;
  rootDefault = builtins.readFile ../../default.nix;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  fleetEquivalenceRawDependency =
    "dependencies = [phase2.gates.singleVmFingerprint.rawGate e2eDeterminism.rawGate phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";
  fleetEquivalenceWrapperDependency =
    "dependencies = [phase2.gates.singleVmFingerprint e2eDeterminism phase7.crucibleFleetStore phase7.crucibleSharedDagStore phase7.crucibleFrontierLeases phase7.crucibleFourLayerDedup phase7.crucibleDeterminismGuardrail phase7.crucibleCasFleetRatchetSeam];";

  failures =
    failuresFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "T-DCE-7 checklist complete";
        needle = "- [x] **T-DCE-7**";
      }
      {
        label = "T-DCE-7 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleDeterminismGuardrail`";
      }
      {
        label = "DCE-16 deterministic reproduction text";
        needle = "**[DCE-16]** **Reproduction MUST be deterministic and host-independent.**";
      }
      {
        label = "DCE-17 nondeterministic scheduling text";
        needle = "**[DCE-17]** **Distribution and scheduling MAY be nondeterministic.**";
      }
      {
        label = "DCE-18 distribution metadata text";
        needle = "Distribution metadata";
      }
      {
        label = "DCE-18 forbidden flow text";
        needle = "MUST NOT flow into";
      }
      {
        label = "DCE-19 harness-lint extension text";
        needle = "`gate:harness-lint` ([HARN-24]) MUST be **extended**";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/35-distributed-continuous-exploration.md" dceDoc [
      {
        label = "stale T-DCE-7 placeholder";
        needle = "- [ ] **T-DCE-7**";
      }
      {
        label = "stale T-DCE-7 guardrail remaining note";
        needle = "Determinism guardrails remain T-DCE-7";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/harness_lint/common.rs" harnessLintCommonRust [
      {
        label = "distribution metadata identifier set";
        needle = "DISTRIBUTION_METADATA_IDENTIFIERS";
      }
      {
        label = "host id metadata identifier";
        needle = "\"host_id\"";
      }
      {
        label = "lease owner metadata identifier";
        needle = "\"lease_owner\"";
      }
      {
        label = "owner metadata alias";
        needle = "\"owner\"";
      }
      {
        label = "lease timestamp metadata identifier";
        needle = "\"lease_timestamp\"";
      }
      {
        label = "claim acquisition tick metadata identifier";
        needle = "\"acquired_at_tick\"";
      }
      {
        label = "fleet size metadata identifier";
        needle = "\"fleet_size\"";
      }
      {
        label = "peer count metadata identifier";
        needle = "\"peer_count\"";
      }
      {
        label = "distribution metadata flow target set";
        needle = "DISTRIBUTION_METADATA_FLOW_TARGETS";
      }
      {
        label = "reduce target";
        needle = "\"reduce\"";
      }
      {
        label = "decision target";
        needle = "\"Decision\"";
      }
      {
        label = "content hash target";
        needle = "\"ContentHash\"";
      }
      {
        label = "artifact target";
        needle = "\"CampaignReplayArtifact\"";
      }
      {
        label = "coordination allowlist";
        needle = "DISTRIBUTION_METADATA_COORDINATION_FUNCTION_TERMS";
      }
      {
        label = "coordination-only target allowlist";
        needle = "DISTRIBUTION_METADATA_COORDINATION_ONLY_TARGETS";
      }
      {
        label = "distribution metadata lint rule";
        needle = "\"distribution-metadata-flow\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/support/harness_lint/scan.rs" harnessLintScanRust [
      {
        label = "custom static analysis calls distribution metadata flow";
        needle = "findings.extend(distribution_metadata_flow_failures(path, content, &tokens));";
      }
      {
        label = "distribution metadata flow scanner";
        needle = "pub(super) fn distribution_metadata_flow_failures";
      }
      {
        label = "flow scanner reads metadata identifiers";
        needle = "DISTRIBUTION_METADATA_IDENTIFIERS";
      }
      {
        label = "flow scanner reads forbidden targets";
        needle = "DISTRIBUTION_METADATA_FLOW_TARGETS";
      }
      {
        label = "coordination-only function exemption";
        needle = "distribution_metadata_function_is_coordination_only";
      }
      {
        label = "owner alias context guard";
        needle = "distribution_metadata_identifier_is_guarded";
      }
      {
        label = "distribution metadata finding";
        needle = "distribution metadata reaching reduce/Decision/content key/artifact path";
      }
      {
        label = "distribution metadata finding rule";
        needle = "\"distribution-metadata-flow\"";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/harness_lint.rs" harnessLintMainRust [
      {
        label = "negative identity-path regression";
        needle = "harness_lint_rejects_distribution_metadata_in_identity_paths";
      }
      {
        label = "coordination allowlist regression";
        needle = "harness_lint_allows_distribution_metadata_in_coordination_paths";
      }
      {
        label = "negative regression checks peer count";
        needle = "metadata_reaches_decision(peer_count";
      }
      {
        label = "negative regression checks reduce";
        needle = "metadata_reaches_reduce(now_tick";
      }
      {
        label = "negative regression rejects coordination-named artifact";
        needle = "claim_replay_artifact(owner";
      }
      {
        label = "negative regression rejects coordination-named reduce";
        needle = "progress_reduce(peer_count";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-harness-lint.nix" phase1HarnessLint [
      {
        label = "phase1 harness-lint records T-DCE-7";
        needle = "T-DCE-7";
      }
      {
        label = "phase1 harness-lint records lint extension";
        needle = "custom_static_tier=rust-harness-lint-all-crucible-src,hash-iteration,default-random-hasher,unordered-select,immediate-safety-comments,distribution-metadata-flow";
      }
      {
        label = "phase1 harness-lint records guardrail";
        needle = "distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 determinism guardrail check imported";
        needle = "crucibleDeterminismGuardrail = import ./phase7-crucible-determinism-guardrail.nix";
      }
      {
        label = "fleet equivalence raw gate waits for determinism guardrail";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "fleet equivalence wrapper waits for determinism guardrail";
        needle = fleetEquivalenceWrapperDependency;
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring expects determinism guardrail";
        needle = "checks.crucible.phase7.crucibleDeterminismGuardrail";
      }
      {
        label = "CI wiring expects determinism guardrail dependency";
        needle = fleetEquivalenceRawDependency;
      }
      {
        label = "CI wiring records determinism guardrail source";
        needle = "determinism_guardrail_source=checks.crucible.phase7.crucibleDeterminismGuardrail";
      }
    ]
    ++ failuresFor "default.nix" rootDefault [
      {
        label = "distributed wrapper consumes determinism guardrail gate";
        needle = "determinismGuardrailGate = crucibleChecks.phase7.crucibleDeterminismGuardrail;";
      }
      {
        label = "distributed wrapper checks determinism guardrail result";
        needle = ''determinism_guardrail_result="''${determinismGuardrailGate}/result"'';
      }
      {
        label = "distributed wrapper records determinism guardrail result";
        needle = ''determinism_guardrail_gate_result=''${determinismGuardrailGate}/result'';
      }
      {
        label = "distributed wrapper records distribution metadata guardrail";
        needle = "distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban";
      }
      {
        label = "distributed wrapper records distribution metadata lint";
        needle = "distribution_metadata_lint=distribution-metadata-flow";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 determinism guardrail check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-determinism-guardrail";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep] ++ dependencies;

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            harness_lint_extension=distribution-metadata-flow
            distribution_metadata_guardrail=reduce-decision-content-key-artifact-ban
            forbidden_paths=reduce,Decision,content-key,artifact
            allowed_paths=claim-lease,affinity,telemetry,progress
            fleet_equivalence_gate_status=implemented
            RESULT
          '';
        }
      ];
    }
