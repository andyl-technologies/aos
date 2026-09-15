##! Derived inventory of package activation ownership.
{pkgs, ...}: let
  packageNames = builtins.filter (name: let
    candidate = builtins.tryEval pkgs.${name};
  in
    candidate.success
    && builtins.isAttrs candidate.value
    && (candidate.value.type or null) == "derivation") (builtins.attrNames pkgs);

  exposes = name: pkgs.${name} ? expose;
  hasAbility = name:
    pkgs.${name} ? abilities && pkgs.${name}.abilities ? contract;
  activationMode = name:
    (builtins.fromJSON (
      builtins.unsafeDiscardStringContext pkgs.${name}.abilities.contract.abilityTemplateJson
    ))
    .activation_mode;
  documentationKind = name:
    pkgs.${name}.passthru.serviceDocumentation.kind or null;
  isFixture = name: documentationKind name == "fixture";

  productionPackages = builtins.filter (name: !isFixture name) packageNames;
  exposedPackages = builtins.filter exposes productionPackages;
  abilityPackages = builtins.filter hasAbility productionPackages;
  activationPackages =
    builtins.filter (
      name: exposes name && activationMode name == "structured-effects"
    )
    abilityPackages;
  contractPackages =
    builtins.filter (
      name: activationMode name == "contracts-only"
    )
    abilityPackages;
  passivePackages =
    builtins.filter (name: !exposes name && !hasAbility name) productionPackages;
  missingActivation = builtins.filter (name: !hasAbility name) exposedPackages;

  require = condition: message:
    if condition
    then true
    else throw message;
in
  assert require (missingActivation == [])
  "production expose packages without structured activation ownership: ${builtins.concatStringsSep ", " missingActivation}";
  assert require (builtins.length activationPackages == builtins.length exposedPackages)
  "every production expose package must use the sole structured activation path"; {
    schema = "aos.package-activation-inventory/v1";
    inherit
      activationPackages
      abilityPackages
      contractPackages
      passivePackages
      ;
  }
