{
  pkgs,
  attrPath ? "checks.crucible.phase9.gates.campaignReleaseAcceptanceContract",
  taskIds ? [],
  dependencies ? [],
}: let
  contractPath = ./campaign-release-acceptance-contract.toml;
  contract = builtins.fromTOML (builtins.readFile contractPath);
  runner = ./_phase9-campaign-release-acceptance.sh;
  expectedExecutableGates = [
    "gate:campaign-gate-matrix"
    "gate:campaign-operational-continuity"
    "gate:campaign-replay"
    "gate:hot-fork-scaling"
    "gate:campaign-required-gates"
    "gate:e2e-determinism"
  ];
  valid =
    contract.schema
    == "aos.crucible.campaign-release-acceptance-contract.v2"
    && contract.gate == "gate:campaign-release-acceptance"
    && contract.acceptance_state == "automated-evidence-required"
    && contract.implementation_tasks
    == [
      "T-CAM-9.1"
      "T-CAM-9.2"
      "T-CAM-9.3"
      "T-CAM-9.4"
      "T-CAM-9.5"
      "T-CAM-9.6"
      "T-CAM-9.7"
    ]
    && contract.executable_evidence.required_gates == expectedExecutableGates
    && contract.e2e_evidence.gate == "gate:e2e-determinism"
    && contract.e2e_evidence.schema == "crucible.e2e.native-gate-evidence.v1"
    && contract.e2e_evidence.live_packaged_qemu_required
    && contract.e2e_evidence.tcg_only
    && contract.e2e_evidence.local_profile_replay_required
    && contract.e2e_evidence.profile_matrix
    == [
      "quiet-single-core"
      "randomized-worker-two-core"
      "loaded-io-stall-four-core"
    ]
    && contract.e2e_evidence.varied_core_counts == [1 2 4]
    && contract.e2e_evidence.randomized_worker_scheduling_required
    && contract.e2e_evidence.wall_clock_jitter_required
    && contract.e2e_evidence.host_io_stall_required
    && contract.e2e_evidence.byte_identical_results_required
    && contract.e2e_evidence.byte_identical_artifact_required
    && builtins.elem "e2e_evidence_result_sha256" contract.provenance.fields
    && builtins.elem "e2e_evidence_manifest_sha256" contract.provenance.fields
    && contract.binding.e2e_evidence_result_sha256_required
    && contract.binding.e2e_evidence_manifest_sha256_required
    && contract.binding.missing_or_mismatched_result == "blocked"
    && contract.output.retains_e2e_evidence
    && contract.output.accepted_result == "pass";
in
  assert valid;
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-release-acceptance-contract";
      version = "0";
      src = null;

      buildDeps =
        [
          pkgs.bash
          pkgs.coreutils
          pkgs.grep
          pkgs.sed
        ]
        ++ dependencies;

      phases = [
        {
          name = "validate-contract-and-negative-controls";
          script = ''
            set -eu
            test_root="$TMPDIR/release-acceptance-contract"
            evidence="$test_root/e2e"
            mkdir -p "$evidence/evidence"

            cat > "$evidence/result" <<'RESULT'
            PASS
            gate=gate:e2e-determinism
            tcg_only=true
            required_system_features=none
            RESULT
            printf 'canonical result\n' > "$evidence/evidence/canonical-results.tsv"
            printf 'command journal\n' > "$evidence/evidence/command-journal.tsv"
            printf 'reproduction artifact\n' > "$evidence/evidence/reproduction.crucible"
            canonical_sha="$(sha256sum "$evidence/evidence/canonical-results.tsv" | cut -d ' ' -f 1)"
            journal_sha="$(sha256sum "$evidence/evidence/command-journal.tsv" | cut -d ' ' -f 1)"
            artifact_sha="$(sha256sum "$evidence/evidence/reproduction.crucible" | cut -d ' ' -f 1)"
            dummy_sha="$(printf 'closure identity\n' | sha256sum | cut -d ' ' -f 1)"
            cat > "$evidence/evidence/manifest.env" <<MANIFEST
            schema=crucible.e2e.native-gate-evidence.v1
            crucible_package_identity=00000000000000000000000000000000-crucible-0
            scenario_sha256=$dummy_sha
            qemu_binary_sha256=$dummy_sha
            qemu_identity_sha256=$dummy_sha
            plugin_sha256=$dummy_sha
            kernel_sha256=$dummy_sha
            root_image_sha256=$dummy_sha
            canonical_results_sha256=$canonical_sha
            command_journal_sha256=$journal_sha
            reproduction_artifact_sha256=$artifact_sha
            profile_matrix=quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core
            producer_profile=quiet-single-core
            reproducer_profile=loaded-io-stall-four-core
            randomized_worker_scheduling=true
            wall_clock_jitter=true
            host_io_stall=true
            varied_core_counts=1,2,4
            live_qemu=true
            tcg_only=true
            MANIFEST
            manifest_sha="$(sha256sum "$evidence/evidence/manifest.env" | cut -d ' ' -f 1)"
            cat > "$evidence/evidence/result" <<RESULT
            PASS
            gate=gate:e2e-determinism
            schema=crucible.e2e.native-gate-evidence.v1
            native_qemu_execution=true
            live_qemu=true
            tcg_only=true
            local_profile_replay=true
            profile_matrix=quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core
            randomized_worker_scheduling=true
            wall_clock_jitter=true
            host_io_stall=true
            varied_core_counts=1,2,4
            canonical_event_logs=byte-identical
            final_fingerprints=byte-identical
            artifact_replay=different-machine-profile-byte-identical
            canonical_results_sha256=$canonical_sha
            reproduction_artifact_sha256=$artifact_sha
            manifest_sha256=$manifest_sha
            RESULT

            ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"

            cp "$evidence/evidence/canonical-results.tsv" "$test_root/canonical.original"
            printf 'tampered result\n' > "$evidence/evidence/canonical-results.tsv"
            if ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"; then
              echo 'release acceptance accepted tampered canonical results' >&2
              exit 1
            fi
            cp "$test_root/canonical.original" "$evidence/evidence/canonical-results.tsv"

            cp "$evidence/evidence/result" "$test_root/result.original"
            sed 's/^manifest_sha256=.*/manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
              "$test_root/result.original" > "$evidence/evidence/result"
            if ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"; then
              echo 'release acceptance accepted a tampered closure manifest digest' >&2
              exit 1
            fi
            cp "$test_root/result.original" "$evidence/evidence/result"

            sed 's/^local_profile_replay=true$/local_profile_replay=false/' \
              "$test_root/result.original" > "$evidence/evidence/result"
            if ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"; then
              echo 'release acceptance accepted an altered local replay result' >&2
              exit 1
            fi
            cp "$test_root/result.original" "$evidence/evidence/result"

            mv "$evidence/evidence/manifest.env" "$test_root/manifest.missing"
            if ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"; then
              echo 'release acceptance accepted missing local e2e evidence' >&2
              exit 1
            fi
            mv "$test_root/manifest.missing" "$evidence/evidence/manifest.env"

            mv "$evidence/evidence/result" "$test_root/result.missing"
            if ${pkgs.bash}/bin/bash ${runner} --probe-e2e-evidence "$evidence"; then
              echo 'release acceptance accepted a missing local e2e result' >&2
              exit 1
            fi
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            cp ${contractPath} "$out/campaign-release-acceptance-contract.toml"
            cat > "$out/required-claim-gates.txt" <<'GATES'
            ${builtins.concatStringsSep "\n" contract.executable_evidence.required_claim_gates}
            GATES
            cat > "$out/result" <<RESULT
            CONTRACT_VALIDATED
            check=${attrPath}
            gate=gate:campaign-release-acceptance
            tasks=${builtins.concatStringsSep "," taskIds}
            schema=aos.crucible.campaign-release-acceptance-contract.v2
            automated_evidence=required
            e2e_evidence=local-live-qemu-required
            negative_controls=missing-evidence,missing-result,tampered-results,tampered-manifest-digest
            RESULT
          '';
        }
      ];
    }
