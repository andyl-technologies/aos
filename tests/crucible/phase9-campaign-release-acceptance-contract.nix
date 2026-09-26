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
    && builtins.elem "gate:campaign-envoy-known-finding" contract.executable_evidence.required_claim_gates
    && builtins.elem "gate:campaign-envoy-product-lifecycle" contract.executable_evidence.required_claim_gates
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
            mv "$test_root/result.missing" "$evidence/evidence/result"

            binding_root="$test_root/binding"
            package="$binding_root/crucible-0"
            qemu="$binding_root/qemu/bin/qemu-system-x86_64"
            plugin="$binding_root/plugin/lib/plugin.so"
            scenario="$binding_root/scenario.toml"
            kernel="$binding_root/vmlinuz"
            root_image="$binding_root/root.ext4"
            qemu_identity="$binding_root/qemu/share/aos/crucible/qemu-build-identity.env"
            release_env="$package/share/aos/crucible/release-manifest.env"
            mkdir -p "$binding_root/qemu/bin" "$binding_root/qemu/share/aos/crucible" \
              "$binding_root/plugin/lib" "$package/share/aos/crucible"
            for source in "$qemu" "$plugin" "$scenario" "$kernel" "$root_image" "$qemu_identity"; do
              printf 'built input: %s\n' "$source" > "$source"
            done
            printf 'qemu_path=%s\nplugin_path=%s\n' "$qemu" "$plugin" > "$release_env"
            sed -i 's|^crucible_package_identity=.*|crucible_package_identity=crucible-0|' \
              "$evidence/evidence/manifest.env"
            for binding in \
              "scenario_sha256:$scenario" \
              "qemu_binary_sha256:$qemu" \
              "qemu_identity_sha256:$qemu_identity" \
              "plugin_sha256:$plugin" \
              "kernel_sha256:$kernel" \
              "root_image_sha256:$root_image"
            do
              key="$(printf '%s' "$binding" | cut -d : -f 1)"
              source="$(printf '%s' "$binding" | cut -d : -f 2-)"
              digest="$(sha256sum "$source" | cut -d ' ' -f 1)"
              sed -i "s|^$key=.*|$key=$digest|" "$evidence/evidence/manifest.env"
            done
            manifest_sha="$(sha256sum "$evidence/evidence/manifest.env" | cut -d ' ' -f 1)"
            sed -i "s|^manifest_sha256=.*|manifest_sha256=$manifest_sha|" \
              "$evidence/evidence/result"
            probe_binding() {
              ${pkgs.bash}/bin/bash ${runner} --probe-e2e-binding \
                "$evidence" "$package" "$release_env" "$scenario" \
                "$qemu" "$plugin" "$kernel" "$root_image"
            }
            probe_binding

            cp "$evidence/evidence/manifest.env" "$test_root/manifest.bound"
            cp "$evidence/evidence/result" "$test_root/result.bound"
            for key in \
              scenario_sha256 qemu_binary_sha256 qemu_identity_sha256 \
              plugin_sha256 kernel_sha256 root_image_sha256 crucible_package_identity
            do
              mismatched=0000000000000000000000000000000000000000000000000000000000000000
              if test "$key" = crucible_package_identity; then
                mismatched=another-package
              fi
              sed "s|^$key=.*|$key=$mismatched|" "$test_root/manifest.bound" \
                > "$evidence/evidence/manifest.env"
              manifest_sha="$(sha256sum "$evidence/evidence/manifest.env" | cut -d ' ' -f 1)"
              sed "s|^manifest_sha256=.*|manifest_sha256=$manifest_sha|" \
                "$test_root/result.bound" > "$evidence/evidence/result"
              if probe_binding; then
                echo "release acceptance accepted a mismatched $key" >&2
                exit 1
              fi
            done
            cp "$test_root/manifest.bound" "$evidence/evidence/manifest.env"
            cp "$test_root/result.bound" "$evidence/evidence/result"

            sed -i 's|^qemu_path=.*|qemu_path=mismatched|' "$release_env"
            if probe_binding; then
              echo 'release acceptance accepted another release QEMU' >&2
              exit 1
            fi
            printf 'qemu_path=%s\nplugin_path=%s\n' "$qemu" "$plugin" > "$release_env"
            sed -i 's|^plugin_path=.*|plugin_path=mismatched|' "$release_env"
            if probe_binding; then
              echo 'release acceptance accepted another release plugin' >&2
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
            gate=gate:campaign-release-acceptance-contract
            tasks=${builtins.concatStringsSep "," taskIds}
            schema=aos.crucible.campaign-release-acceptance-contract.v2
            automated_evidence=required
            e2e_evidence=local-live-qemu-required
            negative_controls=missing-evidence,missing-result,tampered-results,tampered-manifest-digest,mismatched-built-inputs,mismatched-package,mismatched-release-components
            RESULT
          '';
        }
      ];
    }
