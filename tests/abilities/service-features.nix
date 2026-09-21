##! Checks that provider-neutral service policies are implemented by systemd.
{
  lib,
  pkgs,
}: let
  genericSources = builtins.map builtins.readFile [
    ../../lib/abilities/_service-types.nix
    ../../lib/abilities/_service-interfaces.nix
    ../../lib/abilities/_service-declaration.nix
    ../../lib/abilities/interfaces/service-policy.nix
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
  expectedDevicePolicySelector = {
    inherit (systemdDevicePolicy.declaration) name abi;
  };
  polkitDevicePolicies =
    builtins.filter
    (requirement: builtins.elem expectedDevicePolicySelector requirement.accepted_interfaces)
    (builtins.attrValues pkgs.polkit.abilities.requirementTemplates);
  polkitDevicePolicy =
    if builtins.length polkitDevicePolicies == 1
    then builtins.head polkitDevicePolicies
    else throw "Polkit must consume exactly one provider-neutral service device-policy ability";

  selected = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        config.aos.abilities.environment = {
          authority = "test";
          key = "service-features";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "systemd";
        version = pkgs.systemd.version;
        module = ../../pkgs/system/_systemd-abilities/module.nix;
      }
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
  assert polkitDevicePolicy.accepted_interfaces
  == [expectedDevicePolicySelector];
  assert builtins.all
  (selected: selectedInterfaces ? "${selected.alias}")
  (builtins.attrValues policyInterfaces);
  assert builtins.all
  (selected: projectedImplementations ? "${selected.alias}")
  (builtins.attrValues policyInterfaces); true
