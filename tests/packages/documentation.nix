##! tests/packages/documentation.nix — package documentation authority gate.
{
  lib,
  pkgs,
  ...
}: let
  abilityPackages = lib.filterAttrs (_: value: let
    evaluated = builtins.tryEval value;
  in
    evaluated.success
    && builtins.isAttrs evaluated.value
    && lib.isDerivation evaluated.value
    && evaluated.value ? abilities) pkgs;
  packageNames = builtins.attrNames abilityPackages;
  projectionPaths = builtins.map
    (name: abilityPackages.${name}.contract.document)
    packageNames;

  invalidPackages = builtins.filter (name: let
    package = abilityPackages.${name};
    evaluatedAbilities = builtins.tryEval (builtins.toJSON {
      interfaceAliases = builtins.attrNames package.abilities.interfaces;
      implementationAliases = builtins.attrNames package.abilities.implementations;
      requirementAliases = builtins.attrNames package.abilities.requirementTemplates;
      guaranteeAliases = builtins.attrNames package.abilities.guarantees;
    });
    abilities =
      if evaluatedAbilities.success
      then builtins.fromJSON evaluatedAbilities.value
      else {};
  in
    !evaluatedAbilities.success
    || !(abilities ? interfaceAliases)
    || !(abilities ? implementationAliases)
    || !(abilities ? requirementAliases)
    || !(abilities ? guaranteeAliases)
    || !(builtins.isList abilities.interfaceAliases)
    || !(builtins.isList abilities.implementationAliases)
    || !(builtins.isList abilities.requirementAliases)
    || !(builtins.isList abilities.guaranteeAliases)
    || !(package ? module)
    || !(package ? contract))
  packageNames;
in
  if invalidPackages != []
  then
    throw "package ability documentation projections are invalid: ${builtins.concatStringsSep ", " invalidPackages}"
  else
    pkgs.mkDerivation {
      pname = "package-documentation-policy-check";
      version = "0";
      src = null;
      buildDeps = [pkgs.aos-ability-contract-validator];
      outputChecks = {};
      phases = [
        {
          name = "check";
          script = ''
            ${builtins.concatStringsSep "\n" (builtins.map (path: "aos-ability-contract-validator package-projection ${lib.escapeShellArg path}") projectionPaths)}
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
