##! Checks containerd's disabled package projection retains consumed abilities.
{
  pkgs,
  lib,
}: let
  projection = pkgs.containerd.abilities;
  contractRequirementAliases =
    builtins.map
    (requirement: requirement.alias)
    pkgs.containerd.contract.value.requirements;
in
  assert builtins.attrNames projection.interfaces == [];
  assert builtins.attrNames projection.implementations == [];
  assert contractRequirementAliases == builtins.attrNames projection.requirementTemplates;
  assert projection.requirementTemplates != {};
  assert lib.all
  (requirement: requirement.accepted_interfaces != [] && requirement.methods != [])
  (builtins.attrValues projection.requirementTemplates); true
