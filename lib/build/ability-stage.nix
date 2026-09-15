##! Hermetic checked planning and fixed-point resolution for one build stage.
##!
##! This adapter packages the existing desired-state, authenticated policy,
##! PlanningSnapshot, package contracts, and stock fixed-point evaluator. It
##! defines no provider-selection policy of its own.
{
  lib,
  mkDerivation,
  packageRuntime,
}: {
  pname,
  stage,
  authority,
  key,
  baseLib,
  intentModule,
  desiredInput,
  authenticatedPolicySet,
  packageContracts,
}: let
  packageContractPaths = builtins.sort (left: right: left < right) (
    lib.unique (builtins.map builtins.toString packageContracts)
  );
  commonSpec = {
    schema = "aos.ability.build-stage-resolution/v1";
    inherit stage authority key;
    desired_input = builtins.toString desiredInput;
    authenticated_policy_set = builtins.toString authenticatedPolicySet;
    packages = packageContractPaths;
  };
  planningSpec = builtins.toFile
    "${pname}-ability-planning-spec.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON commonSpec));
  planningSnapshot = mkDerivation {
    pname = "${pname}-ability-planning";
    version = "1";
    src = null;
    buildDeps = [packageRuntime desiredInput authenticatedPolicySet] ++ packageContracts;
    phases = [
      {
        name = "plan";
        script = ''
          ${packageRuntime}/bin/aos-package-runtime \
            __ability-plan-build-stage \
            --spec ${lib.escapeShellArg (builtins.toString planningSpec)} \
            --out "$out"
        '';
      }
    ];
    outputChecks.out = {};
    preferLocalBuild = true;
    allowSubstitutes = false;
  };
  resolutionSpec = builtins.toFile
    "${pname}-ability-resolution-spec.json"
    (builtins.unsafeDiscardStringContext (builtins.toJSON (commonSpec
      // {
        base_lib = builtins.toString baseLib;
        intent_module = builtins.toString intentModule;
        planning_artifact = builtins.toString planningSnapshot;
      })));
  resolvedStage = mkDerivation {
    pname = "${pname}-resolved-ability-stage";
    version = "1";
    src = null;
    buildDeps =
      [
        packageRuntime
        baseLib
        intentModule
        desiredInput
        authenticatedPolicySet
        planningSnapshot
      ]
      ++ packageContracts;
    phases = [
      {
        name = "resolve";
        script = ''
          mkdir -p eval-root
          ${packageRuntime}/bin/aos-package-runtime \
            __ability-build-stage \
            --spec ${lib.escapeShellArg (builtins.toString resolutionSpec)} \
            --out "$out" \
            --eval-root "$PWD/eval-root"
        '';
      }
    ];
    outputChecks.out = {};
    preferLocalBuild = true;
    allowSubstitutes = false;
  };
in {
  inherit planningSnapshot resolvedStage;
}
