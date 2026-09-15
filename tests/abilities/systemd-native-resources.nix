##! Fixed-point realization of mount, swap, and device resources through systemd.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  requirement = selected: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    methods = selected.methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  effectsKey = implementation: key:
    lib.abilities.compositionRequestKey {
      inherit implementation key;
      providerInstance = "systemd:manager";
    };
  mountEffectsKey = effectsKey "systemd:mount-resource" "esp";
  swapEffectsKey = effectsKey "systemd:swap-resource" "main";
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "mount-resource";
  };
  evaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        config.aos.abilities = {
          environment = {
            authority = "test";
            key = "systemd-native-resources";
            stage = "host";
          };
          bindings = {
            "test:mount" = {
              request = "consumer:mount";
              implementation = "systemd:mount-resource";
              providerInstance = "systemd:manager";
              slot = "esp";
            };
            "test:mount-effects" = {
              request = mountEffectsKey;
              implementation = "systemd:systemd-mount-effects";
              providerInstance = "systemd:manager";
              slot = "esp";
            };
            "test:swap" = {
              request = "consumer:swap";
              implementation = "systemd:swap-resource";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:swap-effects" = {
              request = swapEffectsKey;
              implementation = "systemd:systemd-swap-effects";
              providerInstance = "systemd:manager";
              slot = "main";
            };
            "test:device" = {
              request = "consumer:device";
              implementation = "systemd:device-presence";
              providerInstance = "systemd:manager";
              slot = "tunnel";
            };
          };
          instances."systemd:manager" = {};
        };
      }
    ];
    packageModules = [
      {
        name = "systemd";
        inherit (pkgs.systemd) version;
        module = pkgs.systemd.module + "/module.nix";
      }
      {
        name = "consumer";
        module.config.aos.abilities = {
          instances.client = {};
          requirementTemplates = {
            mount = requirement interfaces.mountResource;
            swap = requirement interfaces.swapResource;
            device = requirement interfaces.devicePresence;
          };
          requests = {
            mount = {
              requirement = "mount";
              consumer = "client";
              scope = ["esp"];
              parameters = {
                name = "esp";
                enabled = true;
                source = "/dev/disk/by-partlabel/ESP";
                destination = "/boot";
                filesystem = "vfat";
                options = ["umask=0077"];
                timeout_millis = 30000;
              };
            };
            swap = {
              requirement = "swap";
              consumer = "client";
              scope = ["main"];
              parameters = {
                name = "main";
                enabled = true;
                source = "/dev/zram0";
                priority = 100;
              };
            };
            device = {
              requirement = "device";
              consumer = "client";
              scope = ["tunnel"];
              parameters = {
                name = "tunnel";
                device = "/dev/net/tun";
              };
            };
          };
        };
      }
    ];
    selectedProviderModules = [selectedSystemdProvider];
    specialArgs = {
      inherit pkgs;
      artifactLocatorFor = _: throw "native-resource realization contains no artifacts";
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  abilities = evaluation.config.aos.abilities;
  resources = builtins.attrValues abilities.desiredResources;
  resourceByKind = kind:
    builtins.head (builtins.filter (resource: resource.kind == kind) resources);
  mount = resourceByKind "aos.filesystem.mount";
  swap = resourceByKind "aos.memory.swap";
in
  assert builtins.length resources == 2;
  assert mount.realization
  == {
    schema = "aos.systemd.native-resource-realization/v1";
    backend = "mount-unit";
  };
  assert swap.realization
  == {
    schema = "aos.systemd.native-resource-realization/v1";
    backend = "swap-unit";
  };
  assert abilities.compositionRequests.${mountEffectsKey}.parameters.desired == mount.value;
  assert abilities.compositionRequests.${swapEffectsKey}.parameters.desired == swap.value;
  assert abilities.compositionOutputs == {};
  assert abilities.implementations."systemd:mount-resource".handlerDescriptor == null;
  assert builtins.isFunction abilities.implementations."systemd:mount-resource".transition;
  assert abilities.implementations."systemd:systemd-mount-effects".providerModule == null;
  assert abilities.implementations."systemd:systemd-mount-effects".handlerDescriptor.entryPoint == "bin/aos-systemd-provider";
  assert abilities.implementations."systemd:device-presence".providerModule == null;
  assert abilities.implementations."systemd:device-presence".handlerDescriptor.entryPoint == "bin/aos-systemd-provider";
  assert builtins.length evaluation.config.systemd.providerUnitArtifacts == 2; true
