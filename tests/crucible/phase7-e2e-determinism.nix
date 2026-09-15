{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.e2eDeterminism",
  taskIds ? [],
  openTaskIds ? [],
  dependencies ? [],
  crossHostEvidence ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  cliE2eGate = builtins.readFile ../../crates/crucible-cli/tests/gate_e2e_determinism.rs;
  e2eHarness = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  harnessE2eGate = builtins.readFile ../../crates/crucible-harness/tests/gate_e2e_determinism.rs;
  nativeRunner = ./_e2e-determinism-native-runner.sh;
  nativeRunnerSource = builtins.readFile nativeRunner;
  evidenceBuilder = builtins.readFile ./phase7-e2e-determinism-evidence.nix;
  evidenceContract = builtins.readFile ./e2e-determinism-evidence-contract.toml;
  evidenceContractValidator = builtins.readFile ./phase7-e2e-determinism-evidence-contract.nix;
  fleetRunner = builtins.readFile ./_fleet-runner.nix;

  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-cli/tests/gate_e2e_determinism.rs" cliE2eGate [
      {
        label = "CLI modeled artifact component";
        needle = "e2e_artifact_component_runs_mock_fault_and_property_corpus";
      }
      {
        label = "modeled machine-profile replay";
        needle = "e2e_artifact_component_replays_across_modeled_machine_profiles";
      }
      {
        label = "build identity negative control";
        needle = "e2e_artifact_component_rejects_build_identity_drift";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/e2e.rs" e2eHarness [
      {
        label = "representative artifact";
        needle = "pub fn representative_mock_e2e_artifact";
      }
      {
        label = "modeled gate runner";
        needle = "pub fn run_mock_e2e_determinism_gate";
      }
      {
        label = "distinct modeled-profile enforcement";
        needle = "MissingDifferentMachineProfile";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_e2e_determinism.rs" harnessE2eGate [
      {
        label = "hostile-profile artifact comparison";
        needle = "gate_e2e_determinism_runs_fault_injected_multi_vm_artifact_under_adversarial_profiles";
      }
      {
        label = "cross-machine modeled-profile negative control";
        needle = "gate_e2e_determinism_requires_cross_machine_reproduction_profile";
      }
    ]
    ++ failuresFor "tests/crucible/_e2e-determinism-native-runner.sh" nativeRunnerSource [
      {
        label = "native per-host runner";
        needle = "run-host";
      }
      {
        label = "cross-host evidence verifier";
        needle = "verify-cross-host";
      }
      {
        label = "physical-host attestation contract";
        needle = "crucible.e2e.physical-host-attestation.v1";
      }
      {
        label = "distinct physical-host enforcement";
        needle = "cross-host evidence uses one physical-host identity";
      }
      {
        label = "randomized worker profile";
        needle = "randomized-worker-two-core";
      }
      {
        label = "I/O-stall profile";
        needle = "loaded-io-stall-four-core";
      }
      {
        label = "wall-clock launch jitter";
        needle = "launch_jitter";
      }
      {
        label = "bounded scheduler preemption during replay";
        needle = "replay --bounded-scheduler-preemption";
      }
      {
        label = "varied native core matrix";
        needle = "varied_core_counts=1,2,4";
      }
      {
        label = "live packaged QEMU backend";
        needle = "--backend qemu";
      }
      {
        label = "nonempty live fingerprint enforcement";
        needle = "samples=[1-9][0-9]*";
      }
      {
        label = "byte-identical canonical result comparison";
        needle = ''cmp "$producer/canonical-results.tsv" "$reproducer/canonical-results.tsv"'';
      }
      {
        label = "byte-identical reproduction artifact identity";
        needle = "produced_artifact_sha256";
      }
      {
        label = "cross-host replay provenance";
        needle = "second host replayed a different artifact";
      }
      {
        label = "retained raw native transcript";
        needle = ''"$profile_output/verify.jsonl"'';
      }
    ]
    ++ forbiddenFor "tests/crucible/_e2e-determinism-native-runner.sh" nativeRunnerSource [
      {
        label = "host shell path";
        needle = "/bin/sh";
      }
      {
        label = "host bash path";
        needle = "/bin/bash";
      }
      {
        label = "environment shebang";
        needle = "/usr/bin/env";
      }
      {
        label = "false physical cross-host claim";
        needle = "physical_cross_host_reproduction=false";
      }
    ]
    ++ failuresFor "tests/crucible/_fleet-runner.nix" fleetRunner [
      {
        label = "native runner binding";
        needle = "e2eNativeRunner = ./_e2e-determinism-native-runner.sh;";
      }
      {
        label = "native runner environment";
        needle = "export CRUCIBLE_E2E_NATIVE_RUNNER=";
      }
      {
        label = "live QEMU durable process state";
        needle = ''CRUCIBLE_RUN_STATE_ROOT="$FLEET_WORKDIR/run-state"'';
      }
    ]
    ++ failuresFor "tests/crucible/phase7-e2e-determinism-evidence.nix" evidenceBuilder [
      {
        label = "separate physical-host evidence inputs";
        needle = "producerEvidence,";
      }
      {
        label = "release-owner sign-off input";
        needle = "releaseSignOff,";
      }
      {
        label = "retained reproducer host bundle";
        needle = ''"$out/reproducer"'';
      }
      {
        label = "retained command journal";
        needle = ''"$out/command-journal.tsv"'';
      }
      {
        label = "cross-host verifier execution";
        needle = "verify-cross-host";
      }
    ]
    ++ failuresFor "tests/crucible/e2e-determinism-evidence-contract.toml" evidenceContract [
      {
        label = "manual evidence contract schema";
        needle = "aos.crucible.e2e-determinism-evidence-contract.v1";
      }
      {
        label = "manual evidence provenance";
        needle = "[provenance]";
      }
      {
        label = "manual command journal";
        needle = "[command_journal]";
      }
      {
        label = "manual independent sign-offs";
        needle = "[sign_offs]";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-e2e-determinism-evidence-contract.nix" evidenceContractValidator [
      {
        label = "manual contract validator attribute";
        needle = "checks.crucible.phase7.gates.e2eDeterminismEvidenceContract";
      }
      {
        label = "missing evidence remains release-blocking";
        needle = "release_blocker=two-distinct-physical-host-native-transcripts";
      }
    ];

  evidenceDependencies = lib.optional (crossHostEvidence != null) crossHostEvidence;
in
  if failures != []
  then throw "crucible phase7 e2e-determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-e2e-determinism";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.bash
          pkgs.coreutils
          pkgs.grep
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies
        ++ evidenceDependencies;

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
          name = "run-component-and-contract-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-cli \
              --test gate_e2e_determinism \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-phase7-e2e-determinism-target" \
              -p crucible-harness \
              --test gate_e2e_determinism \
              -- --test-threads=1

            ${pkgs.bash}/bin/bash -n ${nativeRunner}

            producer="$TMPDIR/producer"
            reproducer="$TMPDIR/reproducer"
            comparison="$TMPDIR/comparison"
            mkdir -p "$producer" "$reproducer"
            printf 'stable canonical transcript\n' > "$producer/canonical-results.tsv"
            cp "$producer/canonical-results.tsv" "$reproducer/canonical-results.tsv"
            printf 'stable reproduction artifact\n' > "$producer/reproduction.crucible"
            cp "$producer/reproduction.crucible" "$reproducer/reproduction.crucible"
            producer_host="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            reproducer_host="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            cat > "$producer/physical-host-attestation.env" <<EOF
            schema=crucible.e2e.physical-host-attestation.v1
            physical_host_id=$producer_host
            physical_host_kind=physical
            operator_attested=true
            EOF
            cat > "$reproducer/physical-host-attestation.env" <<EOF
            schema=crucible.e2e.physical-host-attestation.v1
            physical_host_id=$reproducer_host
            physical_host_kind=physical
            operator_attested=true
            EOF
            producer_operator="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            reproducer_operator="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            release_operator="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            cat > "$producer/sign-off.env" <<EOF
            schema=crucible.e2e.host-sign-off.v1
            role=producer_host_operator
            physical_host_id=$producer_host
            operator_identity=$producer_operator
            accepted=true
            EOF
            cat > "$reproducer/sign-off.env" <<EOF
            schema=crucible.e2e.host-sign-off.v1
            role=reproducer_host_operator
            physical_host_id=$reproducer_host
            operator_identity=$reproducer_operator
            accepted=true
            EOF
            release_sign_off="$TMPDIR/release-sign-off.env"
            for evidence_host in "$producer" "$reproducer"; do
              for profile in \
                quiet-single-core \
                randomized-worker-two-core \
                loaded-io-stall-four-core
              do
                mkdir -p "$evidence_host/profiles/$profile"
                printf 'block=0000000000000000000000000000000000000000000000000000000000000000\n' \
                  > "$evidence_host/profiles/$profile/store-populate.log"
                printf '{"kind":"final_outcome","status":"passed"}\n' \
                  > "$evidence_host/profiles/$profile/verify.jsonl"
              done
              printf '{"kind":"final_outcome","status":"passed"}\n' \
                > "$evidence_host/replay.jsonl"
              printf 'operation\tprofile\texit_status\tstructured_output\n' \
                > "$evidence_host/command-journal.tsv"
              printf 'populate-store\tquiet-single-core\t0\tprofiles/quiet-single-core/store-populate.log\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'populate-store\trandomized-worker-two-core\t0\tprofiles/randomized-worker-two-core/store-populate.log\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'populate-store\tloaded-io-stall-four-core\t0\tprofiles/loaded-io-stall-four-core/store-populate.log\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'verify\tquiet-single-core\t0\tprofiles/quiet-single-core/verify.jsonl\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'verify\trandomized-worker-two-core\t0\tprofiles/randomized-worker-two-core/verify.jsonl\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'verify\tloaded-io-stall-four-core\t0\tprofiles/loaded-io-stall-four-core/verify.jsonl\n' \
                >> "$evidence_host/command-journal.tsv"
              printf 'replay\tlocal-or-cross-host\t0\treplay.jsonl\n' \
                >> "$evidence_host/command-journal.tsv"
            done
            canonical_digest="$(sha256sum "$producer/canonical-results.tsv" | cut -d ' ' -f 1)"
            artifact_digest="$(sha256sum "$producer/reproduction.crucible" | cut -d ' ' -f 1)"
            producer_attestation="$(sha256sum "$producer/physical-host-attestation.env" | cut -d ' ' -f 1)"
            reproducer_attestation="$(sha256sum "$reproducer/physical-host-attestation.env" | cut -d ' ' -f 1)"
            producer_sign_off="$(sha256sum "$producer/sign-off.env" | cut -d ' ' -f 1)"
            reproducer_sign_off="$(sha256sum "$reproducer/sign-off.env" | cut -d ' ' -f 1)"
            command_journal_digest="$(sha256sum "$producer/command-journal.tsv" | cut -d ' ' -f 1)"
            scenario_digest="$(printf 'scenario\n' | sha256sum | cut -d ' ' -f 1)"
            qemu_binary_digest="$(printf 'qemu-binary\n' | sha256sum | cut -d ' ' -f 1)"
            qemu_identity_digest="$(printf 'qemu-identity\n' | sha256sum | cut -d ' ' -f 1)"
            plugin_digest="$(printf 'plugin\n' | sha256sum | cut -d ' ' -f 1)"
            kernel_digest="$(printf 'kernel\n' | sha256sum | cut -d ' ' -f 1)"
            root_image_digest="$(printf 'root-image\n' | sha256sum | cut -d ' ' -f 1)"
            cat > "$producer/manifest.env" <<EOF
            schema=crucible.e2e.native-host-evidence.v1
            physical_host_id=$producer_host
            physical_host_attestation_sha256=$producer_attestation
            reproduction_role=producer-and-local-reproducer
            host_sign_off_sha256=$producer_sign_off
            crucible_package_identity=00000000000000000000000000000000-crucible-0
            scenario_sha256=$scenario_digest
            qemu_binary_sha256=$qemu_binary_digest
            qemu_identity_sha256=$qemu_identity_digest
            plugin_sha256=$plugin_digest
            kernel_sha256=$kernel_digest
            root_image_sha256=$root_image_digest
            canonical_results_sha256=$canonical_digest
            command_journal_sha256=$command_journal_digest
            produced_artifact_sha256=$artifact_digest
            replayed_artifact_sha256=$artifact_digest
            randomized_worker_scheduling=true
            wall_clock_jitter=true
            host_io_stall=true
            varied_core_counts=1,2,4
            live_qemu=true
            tcg_only=true
            EOF
            sed \
              -e "s/physical_host_id=$producer_host/physical_host_id=$reproducer_host/" \
              -e "s/physical_host_attestation_sha256=$producer_attestation/physical_host_attestation_sha256=$reproducer_attestation/" \
              -e "s/host_sign_off_sha256=$producer_sign_off/host_sign_off_sha256=$reproducer_sign_off/" \
              -e 's/reproduction_role=producer-and-local-reproducer/reproduction_role=cross-host-reproducer/' \
              "$producer/manifest.env" > "$reproducer/manifest.env"
            producer_manifest_digest="$(sha256sum "$producer/manifest.env" | cut -d ' ' -f 1)"
            reproducer_manifest_digest="$(sha256sum "$reproducer/manifest.env" | cut -d ' ' -f 1)"
            cat > "$release_sign_off" <<EOF
            schema=crucible.e2e.release-sign-off.v1
            role=release_owner
            producer_physical_host_id=$producer_host
            reproducer_physical_host_id=$reproducer_host
            operator_identity=$release_operator
            canonical_results_sha256=$canonical_digest
            reproduction_artifact_sha256=$artifact_digest
            producer_manifest_sha256=$producer_manifest_digest
            reproducer_manifest_sha256=$reproducer_manifest_digest
            accepted=true
            EOF

            ${pkgs.bash}/bin/bash ${nativeRunner} \
              verify-cross-host "$producer" "$reproducer" "$release_sign_off" "$comparison"
            grep -q '^PASS$' "$comparison/result"
            grep -q '^physical_cross_host_reproduction=true$' "$comparison/result"

            same_host="$TMPDIR/same-host"
            cp -R "$producer" "$same_host"
            sed 's/reproduction_role=producer-and-local-reproducer/reproduction_role=cross-host-reproducer/' \
              "$same_host/manifest.env" > "$same_host/manifest.new"
            mv "$same_host/manifest.new" "$same_host/manifest.env"
            if ${pkgs.bash}/bin/bash ${nativeRunner} \
              verify-cross-host \
                "$producer" "$same_host" "$release_sign_off" "$TMPDIR/invalid-comparison"
            then
              echo "same-host evidence unexpectedly passed" >&2
              exit 1
            fi

            ${lib.optionalString (crossHostEvidence != null) ''
              verified_evidence="$TMPDIR/verified-cross-host-evidence"
              ${pkgs.bash}/bin/bash ${nativeRunner} verify-cross-host \
                "${crossHostEvidence}/producer" \
                "${crossHostEvidence}/reproducer" \
                "${crossHostEvidence}/release-sign-off.env" \
                "$verified_evidence"
              cmp "$verified_evidence/result" "${crossHostEvidence}/result"
              grep -q '^PASS$' "$verified_evidence/result"
              grep -q '^gate=gate:e2e-determinism$' "$verified_evidence/result"
              grep -q '^physical_cross_host_reproduction=true$' "$verified_evidence/result"
              grep -q '^randomized_worker_scheduling=true$' "$verified_evidence/result"
              grep -q '^wall_clock_jitter=true$' "$verified_evidence/result"
              grep -q '^host_io_stall=true$' "$verified_evidence/result"
              grep -q '^varied_core_counts=1,2,4$' "$verified_evidence/result"
              grep -q '^live_qemu=true$' "$verified_evidence/result"
              grep -q '^tcg_only=true$' "$verified_evidence/result"
            ''}
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out/bin" "$out/share/crucible/e2e-determinism"
            install -m 644 ${nativeRunner} \
              "$out/share/crucible/e2e-determinism/native-runner.sh"
            cat > "$out/bin/crucible-e2e-determinism-native-runner" <<'RUNNER'
            #!${pkgs.bash}/bin/bash
            exec ${pkgs.bash}/bin/bash ${nativeRunner} "$@"
            RUNNER
            chmod 755 "$out/bin/crucible-e2e-determinism-native-runner"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            component=gate:e2e-determinism/native-evidence-contract
            canonical_gate=gate:e2e-determinism
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            canonical_gate_status=${
              if crossHostEvidence == null
              then "release-blocked"
              else "satisfied"
            }
            owner=crucible-harness
            phase=phase7
            native_runner=$out/bin/crucible-e2e-determinism-native-runner
            native_qemu_execution=required
            physical_cross_host_reproduction=${
              if crossHostEvidence == null
              then "missing"
              else "verified"
            }
            randomized_worker_scheduling=required
            wall_clock_jitter=required
            host_io_stall=required
            varied_core_counts=1,2,4
            transcript_schema=crucible.e2e.native-host-evidence.v1
            cross_host_schema=crucible.e2e.cross-host-evidence.v1
            machine_independent_reproduction=checks.crucible.phase7.machineIndependentReproduction
            native_reduction_slice=checks.fleet.crucible-e2e-determinism
            ci_wiring_guard=checks.crucible.phase7.crucibleGateCiWiring
            evidence_input=${
              if crossHostEvidence == null
              then "none"
              else toString crossHostEvidence
            }
            release_blocker=${
              if crossHostEvidence == null
              then "two-distinct-physical-host-native-transcripts"
              else "none"
            }
            RESULT
          '';
        }
      ];
    }
