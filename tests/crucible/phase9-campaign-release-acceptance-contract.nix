{
  pkgs,
  attrPath ? "checks.crucible.phase9.gates.campaignReleaseAcceptanceContract",
  taskIds ? ["T-CAM-9.7"],
  dependencies ? [],
}: let
  contractPath = ./campaign-release-acceptance-contract.toml;
  contract = builtins.fromTOML (builtins.readFile contractPath);
  destructiveRecoveryContractPath = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml;
  destructiveRecoveryContract = builtins.fromTOML (builtins.readFile destructiveRecoveryContractPath);
  destructiveOperationNames = builtins.concatStringsSep "\n"
    destructiveRecoveryContract.command_journal.required_operations;
  expectedExecutableGates = [
    "gate:campaign-gate-matrix"
    "gate:campaign-operational-continuity"
    "gate:campaign-replay"
    "gate:hot-fork-scaling"
  ];
  expectedManualGates = [
    "gate:campaign-operator-acceptance"
    "gate:campaign-destructive-recovery"
    "gate:campaign-dogfood"
    "gate:e2e-determinism"
  ];
  requiredFiles = [
    "manifest.env"
    "result"
    "command-journal.tsv"
    "artifact-manifest.tsv"
    "resource-audit.tsv"
  ];
  valid =
    contract.schema
    == "aos.crucible.campaign-release-acceptance-contract.v1"
    && contract.gate == "gate:campaign-release-acceptance"
    && contract.acceptance_state == "manual-evidence-required"
    && contract.executable_evidence.required_gates == expectedExecutableGates
    && contract.manual_evidence.required_gates == expectedManualGates
    && contract.manual_evidence.schema == "aos.crucible.campaign-manual-evidence.v1"
    && contract.manual_evidence.required_files == requiredFiles
    && contract.provenance.required
    && contract.provenance.fields
    == [
      "release_manifest_sha256"
      "release_manifest_env_sha256"
      "release_manifest_json_sha256"
      "release_acceptance_contract_sha256"
      "manual_contract_sha256"
    ]
    && contract.sign_offs.namespace == "crucible-campaign-manual-evidence"
    && contract.sign_offs.required_roles_source == "subordinate-contract"
    && contract.sign_offs.minimum_distinct_signers == 3
    && contract.sign_offs.distinct_signer_identities_required
    && contract.sign_offs.distinct_signer_key_fingerprints_required
    && contract.sign_offs.trusted_allowed_signers_input_required
    && contract.sign_offs.signed_payload == "sign-offs/<role>.env"
    && contract.sign_offs.unsigned_result == "blocked"
    && contract.binding.release_manifest_sha256_required
    && contract.binding.release_manifest_env_sha256_required
    && contract.binding.release_manifest_json_sha256_required
    && contract.binding.release_acceptance_contract_sha256_required
    && contract.binding.manual_contract_sha256_required
    && contract.binding.result_sha256_required
    && contract.binding.command_journal_sha256_required
    && contract.binding.artifact_manifest_sha256_required
    && contract.binding.artifact_payload_sha256_required
    && contract.binding.structured_output_sha256_required
    && contract.binding.executable_gate_result_sha256_required
    && contract.binding.manual_evidence_result_sha256_required
    && contract.binding.manual_evidence_manifest_sha256_required
    && contract.binding.missing_or_mismatched_result == "blocked"
    && contract.normalized_evidence.command_journal_schema
    == "operation,exit_status,structured_output_path,structured_output_sha256"
    && contract.normalized_evidence.all_command_exit_statuses_zero
    && contract.normalized_evidence.artifact_manifest_schema == "relative_path,sha256"
    && contract.normalized_evidence.artifact_payload_digests_required
    && contract.normalized_evidence.resource_audit_schema == "resource,status"
    && contract.normalized_evidence.required_resource_status == "clean"
    && contract.normalized_evidence.resource_audit_sha256_required
    && contract.normalized_evidence.injection_record_schema
    == "injection,status,backend_scope,prior_state_path,prior_state_sha256,observables_path,observables_sha256,recovery_path,recovery_sha256"
    && contract.normalized_evidence.required_injection_status == "pass"
    && contract.normalized_evidence.injection_records_sha256_required_when_declared
    && contract.normalized_evidence.injection_payload_digests_required
    && contract.normalized_evidence.regular_non_symlink_files_required
    && contract.normalized_evidence.forbidden_recovery_usage == "blocked"
    && contract.normalized_evidence.unexplained_workaround == "blocked"
    && contract.normalized_evidence.hidden_repair == "blocked"
    && contract.output.schema == "aos.crucible.campaign-release-acceptance.v1"
    && contract.output.retains_external_evidence
    && contract.output.retains_manual_contracts
    && contract.output.retains_executable_gate_results
    && contract.output.retains_release_manifest
    && contract.output.retains_release_manifest_env
    && contract.output.retains_release_manifest_json
    && contract.output.retains_signer_key_bindings
    && contract.output.retains_release_acceptance_contract
    && !contract.output.ordinary_source_package_dependency
    && contract.output.accepted_result == "pass";
in
  if !valid
  then throw "campaign release acceptance contract is incomplete"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-release-acceptance-contract";
      version = "0";
      src = contractPath;
      buildDeps = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.grep] ++ dependencies;

      phases = [
        {
          name = "validate-contract";
          script = ''
            set -eu
            test -s "$src"
            test_root="$TMPDIR/campaign-release-contract-negative"
            mkdir -p "$test_root/evidence/artifacts"
            printf 'outside\n' > "$test_root/outside"
            ln -s "$test_root/outside" "$test_root/evidence/artifacts/escape"
            if ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-evidence-file "$test_root/evidence" artifacts/escape
            then
              echo 'release acceptance accepted a symlink evidence payload' >&2
              exit 1
            fi
            printf '%s\n' 'SHA256:first' 'SHA256:first' > "$test_root/reused-keys"
            if ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-distinct-fingerprints "$test_root/reused-keys"
            then
              echo 'release acceptance accepted one key for two roles' >&2
              exit 1
            fi
            printf '%s\n' 'SHA256:first' 'SHA256:second' > "$test_root/distinct-keys"
            ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-distinct-fingerprints "$test_root/distinct-keys"

            mkdir -p "$test_root/journal"
            printf 'structured\n' > "$test_root/journal/structured.out"
            structured_sha=$(sha256sum "$test_root/journal/structured.out" | cut -d ' ' -f 1)
            printf 'operation\texit_status\tstructured_output_path\tstructured_output_sha256\n' \
              > "$test_root/journal/command-journal.tsv"
            printf 'declared\t0\tstructured.out\t%s\n' "$structured_sha" \
              >> "$test_root/journal/command-journal.tsv"
            printf 'operation\tdeclared\n' > "$test_root/journal.spec"
            ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-command-journal "$test_root/journal" "$test_root/journal.spec"

            mkdir -p "$test_root/destructive-journal"
            printf 'structured destructive recovery evidence\n' \
              > "$test_root/destructive-journal/structured.out"
            structured_sha=$(sha256sum \
              "$test_root/destructive-journal/structured.out" | cut -d ' ' -f 1)
            printf 'operation\texit_status\tstructured_output_path\tstructured_output_sha256\n' \
              > "$test_root/destructive-journal/command-journal.tsv"
            while IFS= read -r operation; do
              printf '%s\t0\tstructured.out\t%s\n' "$operation" "$structured_sha" \
                >> "$test_root/destructive-journal/command-journal.tsv"
              printf 'operation\t%s\n' "$operation" \
                >> "$test_root/destructive-journal.spec"
            done <<'OPERATIONS'
            ${destructiveOperationNames}
            OPERATIONS
            ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-command-journal "$test_root/destructive-journal" \
              "$test_root/destructive-journal.spec"
            printf 'undeclared\t0\tstructured.out\t%s\n' "$structured_sha" \
              >> "$test_root/journal/command-journal.tsv"
            if ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-command-journal "$test_root/journal" "$test_root/journal.spec"
            then
              echo 'release acceptance accepted an undeclared journal operation' >&2
              exit 1
            fi
            sed -i '$d' "$test_root/journal/command-journal.tsv"
            cat "$test_root/journal/command-journal.tsv" \
              >> "$test_root/journal/command-journal.tsv.tmp"
            tail -n 1 "$test_root/journal/command-journal.tsv" \
              >> "$test_root/journal/command-journal.tsv.tmp"
            mv "$test_root/journal/command-journal.tsv.tmp" \
              "$test_root/journal/command-journal.tsv"
            if ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-command-journal "$test_root/journal" "$test_root/journal.spec"
            then
              echo 'release acceptance accepted a duplicate journal operation' >&2
              exit 1
            fi

            mkdir -p "$test_root/complete-tree"
            printf 'bound\n' > "$test_root/complete-tree/bound"
            printf 'bound\n' > "$test_root/complete-tree.inventory"
            ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-evidence-tree "$test_root/complete-tree" \
              "$test_root/complete-tree.inventory"
            printf 'extra\n' > "$test_root/complete-tree/extra"
            if ${pkgs.bash}/bin/bash ${./_phase9-campaign-release-acceptance.sh} \
              --probe-evidence-tree "$test_root/complete-tree" \
              "$test_root/complete-tree.inventory"
            then
              echo 'release acceptance accepted an unbound evidence file' >&2
              exit 1
            fi
            mkdir -p "$out"
            cp "$src" "$out/campaign-release-acceptance-contract.toml"
            cat > "$out/result" <<RESULT
            CONTRACT_VALIDATED
            check=${attrPath}
            gate=gate:campaign-release-acceptance
            tasks=${builtins.concatStringsSep "," taskIds}
            executable_evidence=required
            manual_evidence=required
            detached_signatures=required
            external_trusted_signers=required
            acceptance=not-evaluated
            RESULT
          '';
        }
      ];
    }
