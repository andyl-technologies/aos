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
    pkgs.${name} ? abilityContract;
  activationMode = name:
    (builtins.fromJSON (
      builtins.unsafeDiscardStringContext pkgs.${name}.abilityContract.abilityTemplateJson
    ))
    .activation_mode;
  documentationKind = name:
    pkgs.${name}.passthru.serviceDocumentation.kind or null;
  isFixture = name: documentationKind name == "fixture";

  exposedPackages = builtins.filter exposes packageNames;
  abilityPackages = builtins.filter hasAbility packageNames;
  productionStructured =
    builtins.filter (
      name: exposes name && activationMode name == "structured-effects"
    )
    abilityPackages;
  productionContractsOnly =
    builtins.filter (
      name: !isFixture name && activationMode name == "contracts-only"
    )
    abilityPackages;
  testOnlyLegacy =
    builtins.filter (
      name: exposes name && !hasAbility name && isFixture name
    )
    packageNames;
  passive = builtins.filter (name: !exposes name && !hasAbility name) packageNames;
  legacyEffectful =
    builtins.filter (
      name: !hasAbility name && !isFixture name
    )
    exposedPackages;

  require = condition: message:
    if condition
    then true
    else throw message;
in
  assert require (legacyEffectful == [])
  "production expose packages without ability ownership: ${builtins.concatStringsSep ", " legacyEffectful}";
  assert require (builtins.all (name: activationMode name == "structured-effects") productionStructured)
  "derived production service inventory contains a non-structured package";
  assert require (builtins.all (name: activationMode name == "contracts-only") productionContractsOnly)
  "derived contract-only inventory contains another activation mode"; {
    schema = "aos.package-activation-inventory/v1";
    abilityNative = abilityPackages;
    intentionallyUnsupported = testOnlyLegacy;
    passiveNoActivation = passive;
    inherit
      abilityPackages
      legacyEffectful
      passive
      productionContractsOnly
      productionStructured
      testOnlyLegacy
      ;
  }
