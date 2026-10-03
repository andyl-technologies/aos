{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.signalFaultSystem",
  taskIds ? [],
  instructionFaults,
  hardwareFaults,
  pluginInstall,
  blockRealization,
  patchMicrotests,
  checkpointMaterialization,
  replayOracle,
  hotForkAtomicWorld,
  hotForkEquivalence,
  campaignContinuity,
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = builtins.concatStringsSep "," taskIds;
  selectedResultName =
    if campaignComposition == null
    then "result"
    else "raw-result";
  resultOf = gate: "${gate}/${selectedResultName}";
  gateInputs = [
    instructionFaults
    hardwareFaults
    pluginInstall
    blockRealization
    patchMicrotests
    checkpointMaterialization
    replayOracle
    hotForkAtomicWorld
    hotForkEquivalence
    campaignContinuity
  ];
  runtimeInputs = [pkgs.coreutils pkgs.grep];
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase7-signal-fault-system";
    version = "0";
    src = null;
    buildDeps = runtimeInputs ++ gateInputs ++ dependencies;
    phases = [
      {
        name = "certify-current-signal-fault-system";
        script = ''
          set -eu
          mkdir -p "$out/evidence"

          grep -Fxq PASS ${resultOf instructionFaults}
          grep -Fxq 'backend=actual-patched-and-stock-qemu' ${resultOf instructionFaults}
          grep -Eq '^qemu_package_version=11\.' ${resultOf instructionFaults}
          grep -Fxq 'live_x86_64_result_corruption=true' ${resultOf instructionFaults}
          grep -Fxq 'live_aarch64_result_corruption=true' ${resultOf instructionFaults}
          grep -Fxq PASS ${resultOf hardwareFaults}
          grep -Fxq 'backend=actual-patched-and-stock-qemu' ${resultOf hardwareFaults}
          grep -Eq '^qemu_package_version=11\.' ${resultOf hardwareFaults}
          grep -Fxq 'architectures=x86_64,aarch64' ${resultOf hardwareFaults}
          grep -Fxq 'live_mutations=corrected-ecc,x86-mca,aarch64-ras' ${resultOf hardwareFaults}
          grep -Fxq PASS ${resultOf pluginInstall}
          grep -Fxq 'gate=gate:plugin-install-lifecycle' ${resultOf pluginInstall}
          grep -Fxq PASS ${resultOf blockRealization}
          grep -Fxq 'gate=gate:block-realization' ${resultOf blockRealization}
          grep -Fxq PASS ${resultOf patchMicrotests}
          grep -Fxq PASS ${resultOf checkpointMaterialization}
          grep -Fxq PASS ${resultOf replayOracle}
          grep -Fxq PASS ${resultOf hotForkAtomicWorld}
          grep -Fxq 'io=block,ninep' ${resultOf hotForkAtomicWorld}
          grep -Fxq PASS ${resultOf hotForkEquivalence}
          grep -Fxq 'state=network,block,ninep,guest-choice,measurement,signal,permanent-failure' \
            ${resultOf hotForkEquivalence}
          grep -Fxq 'application_http_status=200' ${resultOf hotForkEquivalence}
          grep -Fxq 'inactive_world_reactivation=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'shared_cause=network,block,node' ${resultOf hotForkEquivalence}
          grep -Fxq 'ninep_fault_injection=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'locked_fault_replay_evidence_match=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'pre_event_queue_and_volatile_cache=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'pre_event_exact_restore=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'shared_effect_state_transition=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'child_boundary_matches_capture=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'child_suffix_matches_exact_restore=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'child_suffix_matches_genesis_replay=true' ${resultOf hotForkEquivalence}
          grep -Fxq 'concurrent_live_children=2' ${resultOf hotForkEquivalence}
          grep -Fxq PASS ${resultOf campaignContinuity}

          cp ${resultOf instructionFaults} "$out/evidence/instruction-faults.result"
          cp ${resultOf hardwareFaults} "$out/evidence/hardware-faults.result"
          cp ${resultOf pluginInstall} "$out/evidence/plugin-install.result"
          cp ${resultOf blockRealization} "$out/evidence/block-realization.result"
          cp ${resultOf patchMicrotests} "$out/evidence/patch-microtests.result"
          cp ${resultOf checkpointMaterialization} "$out/evidence/checkpoint-materialization.result"
          cp ${resultOf replayOracle} "$out/evidence/replay-oracle.result"
          cp ${resultOf hotForkAtomicWorld} "$out/evidence/hot-fork-atomic-world.result"
          cp ${resultOf hotForkEquivalence} "$out/evidence/hot-fork-equivalence.result"
          cp ${resultOf campaignContinuity} "$out/evidence/campaign-continuity.result"

          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:signal-fault-system
          tasks=${taskList}
          runtime=guarded-production-qemu
          plugin_protocol=aggregate-current
          fault_domains=instruction,hardware,node,network,block,ninep
          instruction_architectures=x86_64,aarch64
          hardware_architectures=x86_64,aarch64
          shared_cause=network,block,node
          pre_event_queue_and_volatile_cache=true
          pre_event_exact_restore=true
          shared_effect_state_transition=true
          ninep_fault_injection=true
          application_http_status=200
          inactive_world_reactivation=true
          concurrent_live_children=2
          restore=v9-descriptor-backed
          replay=locked-fault,source-bound-oracle
          whole_world_atomicity=true
          RESULT
        '';
      }
    ];
  };
  expectedConfigurationIdentity =
    campaignComposition.system.config.aos.services.crucibleCampaign._runtimeIdentity;
  expectedToplevel = campaignComposition.system.config.system.build.toplevel;
  authenticationScript = ''
    set -eu
    authenticate_same_mode() {
      result="$1"
      test -f "$result"
      test "$(grep -Fxc PASS "$result")" -eq 1
      test "$(grep -Fxc 'campaign_mode=${campaignComposition.mode}' "$result")" -eq 1
      test "$(grep -Fxc 'campaign_configuration_identity=${expectedConfigurationIdentity}' "$result")" -eq 1
      test "$(grep -Fxc 'campaign_toplevel=${expectedToplevel}' "$result")" -eq 1
      test "$(grep -Ec '^executor_derivation=/nix/store/[0-9a-z]+-.+\.drv$' "$result")" -eq 1
      test "$(grep -c '^campaign_mode=' "$result")" -eq 1
      test "$(grep -c '^campaign_configuration_identity=' "$result")" -eq 1
      test "$(grep -c '^campaign_toplevel=' "$result")" -eq 1
      test "$(grep -c '^executor_derivation=' "$result")" -eq 1
    }

    ${lib.concatMapStringsSep "\n" (gate: "authenticate_same_mode ${lib.escapeShellArg (resultOf gate)}") gateInputs}
  '';
  aggregateScript = (builtins.elemAt authoritativeGate.passthru.phases 0).script;
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeInputs;
      inherit (campaignComposition) mode system;
      gateName = "gate:signal-fault-system";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "signal-fault-system";
      runtimeClosures = gateInputs;
      runtimeScript = authenticationScript + aggregateScript;
    }
  else authoritativeGate
