##! Defines exact-subject qualification for native ability activation and recovery.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  nativeAdapterMatrix = import ./_native-adapter-matrix.nix {inherit lib;};
  requiredInvalidation = ["subject" "policy" "executor" "environment"];
  requiredChecks = {
    ability-native-activation = [
      "authenticated-package-policy-and-operator-authority"
      "exact-interface-binding-effect-plan-and-artifact-identities"
      "consumer-scoped-access-and-independent-service-observation"
      "aggregate-publication-reload-and-unchanged-input-no-op"
      "post-publication-reload-failure-retains-new-configuration-and-old-or-unknown-consumer-state"
      "rollback-revalidates-and-retains-transaction-evidence"
    ];
    ability-native-image-rollout = [
      "advisory-exact-candidate-staging-without-selection-or-reboot"
      "authenticated-rollout-plan-and-exact-native-request"
      "booted-candidate-health-hook-before-config-generation-commit"
      "healthy-provider-and-journal-evidence-before-physical-commit"
      "failed-health-mark-reboot-and-predecessor-retention"
      "exact-generation-roots-and-uki-retention"
      "post-expiry-rollout-root-retirement"
    ];
    ability-native-kubernetes = [
      "authenticated-k3s-bootstrap-and-provider-authority"
      "exact-service-and-kubernetes-object-resource-mapping"
      "consumer-observed-kubernetes-readiness"
      "forged-mapping-grant-and-namespace-rejected-without-mutation"
      "object-update-removal-and-retained-owner-evidence"
      "bounded-bootstrap-planning-rejections-before-effect-construction"
    ];
    ability-native-postgresql = [
      "authenticated-provider-bindings-and-exact-handler-artifacts"
      "exact-seven-operation-ten-edge-provisioning-graph"
      "runtime-output-data-flow-and-schema-valid-observations"
      "loopback-sql-readiness-and-enforced-non-loopback-denial"
      "stopped-divergent-and-child-drift-reconciliation"
      "exact-six-operation-five-edge-teardown-and-persistent-retention"
    ];
    ability-native-recovery = [
      "exact-boot-initrd-artifact-and-static-stage-handoff-contract"
      "process-loss-after-external-effect-reconciles-before-retry"
      "power-loss-after-external-effect-reconciles-after-boot"
      "fresh-receiving-authority-and-resource-incarnations"
      "retained-plan-journal-and-independent-service-observation"
      "gc-after-crashed-unlocked-partial-activation-retains-recovery-set"
    ];
    ability-native-adapter-matrix = [nativeAdapterMatrix.check];
  };
  requiredRegressions = {
    ability-native-activation = ["checks.fleet.ability-native-activation"];
    ability-native-image-rollout = ["checks.fleet.ability-native-image-rollout"];
    ability-native-kubernetes = ["checks.fleet.ability-native-kubernetes"];
    ability-native-postgresql = ["checks.fleet.ability-native-postgresql"];
    ability-native-recovery = ["checks.fleet.ability-native-power-loss"];
    ability-native-adapter-matrix = nativeAdapterMatrix.requirement.regressions;
  };
  requiredProductionOnly = {
    ability-native-activation = false;
    ability-native-image-rollout = true;
    ability-native-kubernetes = false;
    ability-native-postgresql = false;
    ability-native-recovery = false;
    ability-native-adapter-matrix = true;
  };
  preservesRequiredValues = id: let
    requirement = cfg.requirements.${id};
  in
    requirement.phase
    == "staging"
    && requirement.scope == "release"
    && requirement.method == "automated"
    && requirement.production_only == requiredProductionOnly.${id}
    && builtins.all (value: builtins.elem value requirement.invalidated_by) requiredInvalidation
    && builtins.all (value: builtins.elem value requirement.checks) requiredChecks.${id}
    && builtins.all (value: builtins.elem value requirement.regressions) requiredRegressions.${id};
in {
  config.qualification = {
    # Release scope binds each case to every finalized non-control artifact.
    # This covers the exact package, provider, handler and image bytes rather
    # than treating a source-tree fleet result as evidence for a later release.
    requirements = {
      ability-native-activation = {
        phase = "staging";
        scope = "release";
        method = "automated";
        production_only = false;
        checks = requiredChecks.ability-native-activation;
        regressions = requiredRegressions.ability-native-activation;
        invalidated_by = requiredInvalidation;
      };
      ability-native-image-rollout = {
        phase = "staging";
        scope = "release";
        method = "automated";
        production_only = true;
        checks = requiredChecks.ability-native-image-rollout;
        regressions = requiredRegressions.ability-native-image-rollout;
        invalidated_by = requiredInvalidation;
      };
      ability-native-kubernetes = {
        phase = "staging";
        scope = "release";
        method = "automated";
        production_only = false;
        checks = requiredChecks.ability-native-kubernetes;
        regressions = requiredRegressions.ability-native-kubernetes;
        invalidated_by = requiredInvalidation;
      };
      ability-native-postgresql = {
        phase = "staging";
        scope = "release";
        method = "automated";
        production_only = false;
        checks = requiredChecks.ability-native-postgresql;
        regressions = requiredRegressions.ability-native-postgresql;
        invalidated_by = requiredInvalidation;
      };
      ability-native-recovery = {
        phase = "staging";
        scope = "release";
        method = "automated";
        production_only = false;
        checks = requiredChecks.ability-native-recovery;
        regressions = requiredRegressions.ability-native-recovery;
        invalidated_by = requiredInvalidation;
      };
      ability-native-adapter-matrix = nativeAdapterMatrix.requirement;
    };
    assertions = [
      {
        assertion = builtins.all preservesRequiredValues (builtins.attrNames requiredRegressions);
        message = "Ability qualification must retain staging release subjects, direct execution and its source regression coverage.";
      }
      {
        assertion =
          nativeAdapterMatrix.cell_count
          == 1316
          && nativeAdapterMatrix.missing_production_vm_cells == nativeAdapterMatrix.cell_count;
        message = "Every native adapter method and failure boundary must retain a mandatory production-VM qualification cell.";
      }
    ];
  };
}
