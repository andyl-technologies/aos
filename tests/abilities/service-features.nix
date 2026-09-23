##! Checks that provider-neutral service policies are implemented by systemd.
{
  lib,
  pkgs,
}: let
  genericSources = builtins.map builtins.readFile [
    ../../modules/abilities/_service-types.nix
    ../../modules/abilities/_service-interfaces.nix
    ../../modules/abilities/_service-declaration.nix
    ../../modules/abilities/_interfaces/service-policy.nix
  ];
  genericSourcesArePlatformNeutral =
    builtins.all
    (source:
      !lib.hasInfix "linux_" source
      && !lib.hasInfix "aos.platform.linux" source)
    genericSources;

  servicePolicy = lib.abilities.interfaces.servicePolicy;
  policyInterfaces = servicePolicy.interfaces;
  projectedImplementations = pkgs.systemd.abilities.implementations;
  expectedInterfaceNames = [
    "aos.service.device-policy"
    "aos.service.hardening"
    "aos.service.runtime-conditions"
  ];

  systemdDevicePolicy = policyInterfaces.devicePolicy;
  polkitDevicePolicies =
    builtins.filter
    (requirement: (requirement.interface or null) == systemdDevicePolicy.declaration.name)
    (builtins.attrValues selected.config.aos.abilities.requirementTemplates);
  polkitDevicePolicy =
    if builtins.length polkitDevicePolicies == 1
    then builtins.head polkitDevicePolicies
    else throw "Polkit must consume exactly one provider-neutral service device-policy ability";

  selected = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/default.nix
      {
        config.aos.abilities.environment = {
          authority = "test";
          key = "service-features";
          stage = "host";
        };
      }
    ];
    packageModules = [
      (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
      (lib.abilities.authenticatedPackageModuleRecordFor pkgs.polkit)
    ];
  };
  selectedInterfaces = selected.config.aos.abilities.interfaces;
in
  assert genericSourcesArePlatformNeutral;
  assert builtins.attrNames policyInterfaces == ["devicePolicy" "hardening" "runtimeConditions"];
  assert builtins.map
  (name: policyInterfaces.${name}.declaration.name)
  (builtins.attrNames policyInterfaces)
  == expectedInterfaceNames;
  assert polkitDevicePolicy.abi == systemdDevicePolicy.declaration.abi;
  assert polkitDevicePolicy.descriptor == systemdDevicePolicy.identity.descriptor;
  assert builtins.all
  (selected: selectedInterfaces ? "${selected.alias}")
  (builtins.attrValues policyInterfaces);
  assert builtins.all
  (selected: projectedImplementations ? "${selected.alias}")
  (builtins.attrValues policyInterfaces); true
