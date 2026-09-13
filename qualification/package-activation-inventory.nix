##! Closed inventory of package activation ownership.
{
  pkgs,
  lib,
}: let
  productionStructured = [
    "cloudcore"
    "conntrack-tools"
    "containerd"
    "edgecore"
    "envoy"
    "etcd"
    "garage"
    "k3s-combined"
    "k3s-control-plane"
    "k3s-worker"
    "krb5"
    "kubelet"
    "mariadb"
    "nginx"
    "openldap"
    "postgresql"
    "rsync"
  ];
  productionContractsOnly = ["cilium" "k3s"];
  testOnlyLegacy = [
    "aos-registry-server"
    "aos-secret-reference-test"
    "aos-test-agent"
    "apm-systemd-client-test"
    "desired-config-test"
    "desired-prune-test"
    "expose-smoke"
    "landlock-argv-test"
    "test-http-server"
    "test-static-cache-server"
  ];

  packageNames = builtins.filter (name: let
    candidate = builtins.tryEval pkgs.${name};
  in
    candidate.success
    && builtins.isAttrs candidate.value
    && (candidate.value.type or null) == "derivation") (builtins.attrNames pkgs);
  exposes = name: pkgs.${name} ? expose;
  hasAbility = name:
    pkgs.${name} ? abilities
    && (pkgs.${name}.abilities.passthru.abilityPackage or false);
  exposedPackages = builtins.filter exposes packageNames;
  abilityPackages = builtins.filter hasAbility packageNames;
  passive = builtins.filter (name: !exposes name && !hasAbility name) packageNames;
  unsupportedClassificationErrors =
    builtins.filter (
      name: !exposes name || hasAbility name
    )
    testOnlyLegacy;
  legacyEffectful =
    builtins.filter (
      name: !(builtins.elem name testOnlyLegacy) && !hasAbility name
    )
    exposedPackages;
  unknownExposed =
    builtins.filter (
      name:
        !(builtins.elem name productionStructured)
        && !(builtins.elem name testOnlyLegacy)
    )
    exposedPackages;
  missingStructured =
    builtins.filter (
      name: let
        ability = builtins.fromJSON (
          builtins.unsafeDiscardStringContext pkgs.${name}.abilities.abilityTemplateJson
        );
      in
        !hasAbility name || ability.activation_mode != "structured-effects"
    )
    productionStructured;
  missingContractsOnly =
    builtins.filter (
      name: let
        ability = builtins.fromJSON (
          builtins.unsafeDiscardStringContext pkgs.${name}.abilities.abilityTemplateJson
        );
      in
        !hasAbility name || ability.activation_mode != "contracts-only"
    )
    productionContractsOnly;
  require = condition: message:
    if condition
    then true
    else throw message;
in
  assert require (unknownExposed == [])
  "package activation inventory has unclassified exposed packages: ${builtins.concatStringsSep ", " unknownExposed}";
  assert require (legacyEffectful == [])
  "production expose packages without ability ownership: ${builtins.concatStringsSep ", " legacyEffectful}";
  assert require (missingStructured == [])
  "production services missing structured activation: ${builtins.concatStringsSep ", " missingStructured}";
  assert require (missingContractsOnly == [])
  "payload or contributor packages changed activation ownership: ${builtins.concatStringsSep ", " missingContractsOnly}";
  assert require (unsupportedClassificationErrors == [])
  "intentionally unsupported packages changed activation shape: ${builtins.concatStringsSep ", " unsupportedClassificationErrors}"; {
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
