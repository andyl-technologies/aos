##! Systemd publications for provider-neutral network and filesystem readiness.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  requirement = selected: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    methods = ["observe"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  baseBindings = {
    "test:network" = {
      request = "consumer:network";
      implementation = "systemd:network-readiness";
      providerInstance = "systemd:manager";
      slot = "network";
    };
    "test:filesystems" = {
      request = "consumer:filesystems";
      implementation = "systemd:filesystem-readiness";
      providerInstance = "systemd:manager";
      slot = "filesystems";
    };
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        config.aos.abilities = {
          environment = {
            authority = "test";
            key = "systemd-readiness";
            stage = "host";
          };
          inherit bindings;
        };
      }
      ];
      packageModules = [
      {
        name = "systemd";
        module = {
          imports = [
            ../../pkgs/system/_systemd-abilities.nix
            ../../pkgs/system/_systemd-provider.nix
          ];
          config.aos.abilities.instances.manager = {};
        };
      }
      {
        name = "consumer";
        module.config.aos.abilities = {
          instances.application = {};
          requirementTemplates = {
            network = requirement serviceManagement.interfaces.networkReadiness;
            filesystems = requirement serviceManagement.interfaces.filesystemReadiness;
          };
          requests = {
            network = {
              requirement = "network";
              consumer = "application";
              scope = ["network"];
              parameters = {
                scope = "configured-connectivity";
                address_families = ["ipv4" "ipv6"];
              };
            };
            filesystems = {
              requirement = "filesystems";
              consumer = "application";
              scope = ["filesystems"];
              parameters.scope = "local-filesystems";
            };
          };
        };
      }
      ];
      specialArgs = {
        inherit pkgs;
        packageName = "systemd";
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pending = evaluate baseBindings;
  pendingChildren = builtins.attrValues pending.config.aos.abilities.compositionPendingRequests;
  networkChild = builtins.head (builtins.filter
    (child: child.declaration.parameters ? address_families)
    pendingChildren);
  filesystemChild = builtins.head (builtins.filter
    (child: !(child.declaration.parameters ? address_families))
    pendingChildren);
  evaluation = evaluate (baseBindings
    // {
      "test:network-effects" = {
        request = networkChild.request;
        implementation = "systemd:systemd-network-readiness-effects";
        providerInstance = "systemd:manager";
        slot = networkChild.slot;
      };
      "test:filesystem-effects" = {
        request = filesystemChild.request;
        implementation = "systemd:systemd-filesystem-readiness-effects";
        providerInstance = "systemd:manager";
        slot = filesystemChild.slot;
      };
    });
  abilities = evaluation.config.aos.abilities;
  networkOutput = abilities.compositionOutputs."consumer:network".readiness-resource;
  filesystemOutput = abilities.compositionOutputs."consumer:filesystems".readiness-resource;
  resources = builtins.attrValues abilities.resolvedResources;
  resourceFor = reference:
    builtins.head (builtins.filter (resource: resource.resource == reference.resource) resources);
  network = resourceFor networkOutput.value;
  filesystems = resourceFor filesystemOutput.value;
in
  assert builtins.length resources == 2;
  assert network.controller == null;
  assert network.realization == null;
  assert network.value.scope == "configured-connectivity";
  assert filesystems.controller == null;
  assert filesystems.realization == null;
  assert filesystems.value.scope == "local-filesystems";
  assert abilities.implementations."systemd:network-readiness".handlerDescriptor == null;
  assert abilities.implementations."systemd:filesystem-readiness".handlerDescriptor == null;
  assert abilities.implementations."systemd:systemd-network-readiness-effects".providerModule == null;
  assert abilities.implementations."systemd:systemd-filesystem-readiness-effects".providerModule == null; true
