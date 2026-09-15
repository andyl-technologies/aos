##! tests/packages/documentation.nix — package documentation authority gate.
{
  lib,
  pkgs,
  ...
}: let
  allowedConceptualGuides = [
    "README.md"
    "ability-inspection.md"
    "access-control.md"
    "auditing.md"
    "certificates.md"
    "cli.md"
    "configuration.md"
    "deployment.md"
    "host-nix.md"
    "installation.md"
    "networking.md"
    "operations.md"
    "package-authoring.md"
    "package-sandbox.md"
    "packages.md"
    "quickstart.md"
    "recovery.md"
    "registries.md"
    "secrets.md"
    "secure-boot.md"
    "security-hardening.md"
    "support-status.md"
    "troubleshooting.md"
    "upgrades.md"
  ];
  observedGuides = lib.sort builtins.lessThan (lib.filter
    (name: lib.hasSuffix ".md" name)
    (builtins.attrNames (builtins.readDir ../../docs/users/aos)));

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
  if observedGuides != allowedConceptualGuides
  then
    throw ''
      docs/users/aos may contain only the reviewed conceptual guides. Package
      option and ability reference belongs in the package's ordinary module
      declarations so every authenticated documentation surface is generated
      from the checked package projection.
    ''
  else if invalidPackages != []
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
