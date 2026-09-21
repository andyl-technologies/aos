{
  pkgs,
  attrPath ? "checks.crucible.phase7.gates.e2eDeterminismEvidenceContract",
  taskIds ? [],
  dependencies ? [],
}: let
  contractPath = ./e2e-determinism-evidence-contract.toml;
  contract = builtins.fromTOML (builtins.readFile contractPath);
  requiredProvenance = [
    "crucible_package_identity"
    "scenario_sha256"
    "qemu_binary_sha256"
    "qemu_identity_sha256"
    "plugin_sha256"
    "kernel_sha256"
    "root_image_sha256"
    "physical_host_id"
    "physical_host_attestation_sha256"
  ];
  requiredArtifacts = [
    "producer/manifest.env"
    "producer/physical-host-attestation.env"
    "producer/sign-off.env"
    "producer/command-journal.tsv"
    "producer/canonical-results.tsv"
    "producer/reproduction.crucible"
    "producer/profiles/*/store-populate.log"
    "producer/profiles/*/verify.jsonl"
    "reproducer/manifest.env"
    "reproducer/physical-host-attestation.env"
    "reproducer/sign-off.env"
    "reproducer/command-journal.tsv"
    "reproducer/canonical-results.tsv"
    "reproducer/profiles/*/store-populate.log"
    "reproducer/replay.jsonl"
    "release-sign-off.env"
    "command-journal.tsv"
    "result"
  ];
  containsAll = expected: actual:
    builtins.all (item: builtins.elem item actual) expected;
  valid =
    contract.schema
    == "aos.crucible.e2e-determinism-evidence-contract.v1"
    && contract.gate == "gate:e2e-determinism"
    && contract.acceptance_state == "manual-evidence-required"
    && contract.physical_cross_host_required
    && contract.minimum_distinct_physical_hosts >= 2
    && contract.live_packaged_qemu_required
    && contract.tcg_only
    && contract.varied_core_counts == [1 2 4]
    && contract.hostile_profiles
    == ["quiet-single-core" "randomized-worker-two-core" "loaded-io-stall-four-core"]
    && contract.provenance.required
    && containsAll requiredProvenance contract.provenance.fields
    && contract.provenance.exact_closure_match_required
    && contract.provenance.distinct_physical_host_attestations_required
    && contract.command_journal.required
    && contract.command_journal.records_exit_status
    && contract.command_journal.records_structured_output
    && contract.command_journal.redacts_secrets
    && contract.command_journal.required_operations
    == ["populate-store" "verify" "replay" "verify-cross-host"]
    && contract.matrix.randomized_worker_scheduling
    && contract.matrix.wall_clock_jitter
    && contract.matrix.host_io_stall
    && contract.matrix.bounded_scheduler_preemption
    && contract.matrix.required_core_counts == [1 2 4]
    && contract.artifacts.required
    && containsAll requiredArtifacts contract.artifacts.items
    && contract.artifacts.byte_identical_reproduction_artifact_required
    && contract.artifacts.byte_identical_canonical_results_required
    && contract.sign_offs.required_roles
    == ["producer_host_operator" "reproducer_host_operator" "release_owner"]
    && contract.sign_offs.distinct_operator_identities_required
    && contract.sign_offs.unsigned_result == "blocked"
    && contract.acceptance.accepted_result == "pass"
    && contract.acceptance.same_host_result == "blocked"
    && contract.acceptance.missing_evidence_result == "blocked"
    && !contract.acceptance.retry_to_obtain_pass_permitted;
in
  if !valid
  then throw "e2e determinism manual evidence contract is incomplete"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-e2e-determinism-evidence-contract";
      version = "0";
      src = contractPath;
      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "validate-contract";
          script = ''
            set -eu
            test -s "$src"
            mkdir -p "$out"
            cp "$src" "$out/e2e-determinism-evidence-contract.toml"
            cat > "$out/result" <<RESULT
            CONTRACT_VALIDATED
            check=${attrPath}
            gate=gate:e2e-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            physical_cross_host=required
            minimum_distinct_physical_hosts=2
            native_matrix=required
            manual_evidence=required
            acceptance=not-evaluated
            release_blocker=two-distinct-physical-host-native-transcripts
            RESULT
          '';
        }
      ];
    }
