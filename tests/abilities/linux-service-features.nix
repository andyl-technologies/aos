##! Checks that Linux service facets are selected with the Linux platform package.
{
  lib,
  pkgs,
}: let
  genericSources = builtins.map builtins.readFile [
    ../../lib/abilities/_service-types.nix
    ../../lib/abilities/_service-interfaces.nix
    ../../lib/abilities/_service-declaration.nix
  ];
  genericSourcesArePlatformNeutral =
    builtins.all
    (source:
      !lib.hasInfix "linux_" source
      && !lib.hasInfix "aos.platform.linux" source)
    genericSources;

  projectedInterfaces = pkgs.systemd.abilities.interfaces;
  projectedLinuxInterfaces =
    builtins.intersectAttrs {
      linux-service-conditions = null;
      linux-service-device-policy = null;
      linux-service-isolation = null;
    }
    projectedInterfaces;
  expectedLinuxInterfaceNames = [
    "aos.platform.linux.service-conditions"
    "aos.platform.linux.service-device-policy"
    "aos.platform.linux.service-isolation"
  ];

  systemdDevicePolicy = projectedInterfaces.linux-service-device-policy;
  expectedDevicePolicySelector = {
    inherit (systemdDevicePolicy) name abi;
  };
  polkitDevicePolicies =
    builtins.filter
    (requirement: builtins.elem expectedDevicePolicySelector requirement.accepted_interfaces)
    (builtins.attrValues pkgs.polkit.abilities.requirementTemplates);
  polkitDevicePolicy =
    if builtins.length polkitDevicePolicies == 1
    then builtins.head polkitDevicePolicies
    else throw "Polkit must consume exactly one Linux service device-policy ability";

  selected = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        config.aos.abilities.environment = {
          authority = "test";
          key = "linux-service-features";
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
  assert builtins.attrNames projectedLinuxInterfaces
  == [
    "linux-service-conditions"
    "linux-service-device-policy"
    "linux-service-isolation"
  ];
  assert builtins.map
  (name: projectedLinuxInterfaces.${name}.name)
  (builtins.attrNames projectedLinuxInterfaces)
  == expectedLinuxInterfaceNames;
  assert polkitDevicePolicy.accepted_interfaces
  == [expectedDevicePolicySelector];
  assert builtins.all
  (name: selectedInterfaces ? "systemd:${name}")
  (builtins.attrNames projectedLinuxInterfaces); true
