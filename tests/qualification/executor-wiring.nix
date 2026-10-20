##! Checks that release scenarios resolve to the production executor and regressions.
{
  pkgs,
  lib,
  contract,
  fleet,
  releaseQualificationScenarios,
  releaseQualificationCaseScenarios,
}: let
  abilityRequirementIds = map (requirement: requirement.id) (
    builtins.filter (requirement: lib.hasPrefix "ability-" requirement.id) contract.requirements
  );
  packageCaseScenarioNames = builtins.sort builtins.lessThan (map
    (rule: "package-function/${rule.name}/x86_64-linux")
    (builtins.filter (rule: (rule.execution or null) != null) contract.package_rules));
  imageRecovery = builtins.head (
    builtins.filter (requirement: requirement.id == "image-update-recovery") contract.requirements
  );
in
  assert builtins.elem "checks.fleet.measured-boot" imageRecovery.regressions;
  assert builtins.hasAttr "measured-boot" fleet;
  assert builtins.all (id: builtins.hasAttr id releaseQualificationScenarios) abilityRequirementIds;
  assert builtins.hasAttr "package-function" releaseQualificationScenarios;
  assert builtins.hasAttr "claim-container-x86_64-linux-functional" releaseQualificationScenarios;
  assert builtins.hasAttr "claim-disk-x86_64-linux-functional" releaseQualificationScenarios;
  assert builtins.attrNames releaseQualificationCaseScenarios
  == packageCaseScenarioNames;
    pkgs.writeTextFile {
      name = "aos-qualification-executor-wiring-check";
      destination = "/result";
      text = "Release executor scenarios resolve to production checks.\n";
    }
