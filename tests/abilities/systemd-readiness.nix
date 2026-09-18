##! Systemd realization of provider-neutral readiness and activation milestones.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "network-readiness";
  };
  requirement = selected: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    methods = ["observe"];
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  testRuntimeEntry = {
    kind = "directory";
    path = "/run/example";
    mode = "0750";
    owner = "root";
    group = "root";
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
    "test:milestone" = {
      request = "consumer:milestone";
      implementation = "systemd:activation-milestone";
      providerInstance = "systemd:manager";
      slot = "milestone";
    };
    "test:runtime-entries" = {
      request = "consumer:runtime-entries";
      implementation = "systemd:runtime-entry-population";
      providerInstance = "systemd:manager";
      slot = "runtime-entries";
    };
  };
  consumerModule = {
    config.aos.abilities = {
      instances.application = {};
      requirementTemplates = {
        network = requirement serviceManagement.interfaces.networkReadiness;
        filesystems = requirement serviceManagement.interfaces.filesystemReadiness;
        milestone = requirement serviceManagement.interfaces.activationMilestone;
        runtime-entries = requirement serviceManagement.interfaces.runtimeEntryPopulation;
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
        milestone = {
          requirement = "milestone";
          consumer = "application";
          scope = ["milestone"];
          parameters.milestone = "interactive-console";
        };
        runtime-entries = {
          requirement = "runtime-entries";
          consumer = "application";
          scope = ["runtime-entries"];
          parameters.entries = [testRuntimeEntry];
        };
      };
    };
  };
  evaluate = {
    bindings,
    abilityResolution ? {},
  }:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-readiness";
              stage = "host";
            };
            instances."systemd:manager" = {};
            inherit bindings;
          };
        }
      ];
      packageModules = [
        (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
        {
          name = "consumer";
          module = consumerModule;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs abilityResolution;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pending = evaluate {bindings = baseBindings;};
  pendingChildren = builtins.attrValues pending.config.aos.abilities.compositionPendingRequests;
  childFor = field:
    builtins.head (builtins.filter
      (child: builtins.hasAttr field child.declaration.parameters.expected)
      pendingChildren);
  networkChild = childFor "address_families";
  filesystemChild = builtins.head (builtins.filter
    (child:
      (child.declaration.parameters.expected.scope or null) == "local-filesystems")
    pendingChildren);
  milestoneChild = childFor "milestone";
  runtimeEntriesChild = builtins.head (builtins.filter
    (child:
      (child.declaration.parameters.expected.entries or []) != [])
    pendingChildren);
  resolvedAbilityInputs = import ./_composition-resolution.nix {
    abilities = pending.config.aos.abilities;
  };
  evaluation = evaluate {
    bindings =
      baseBindings
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
        "test:milestone-effects" = {
          request = milestoneChild.request;
          implementation = "systemd:systemd-activation-milestone-effects";
          providerInstance = "systemd:manager";
          slot = milestoneChild.slot;
        };
        "test:runtime-entry-effects" = {
          request = runtimeEntriesChild.request;
          implementation = "systemd:systemd-runtime-entry-population-effects";
          providerInstance = "systemd:manager";
          slot = runtimeEntriesChild.slot;
        };
      };
    abilityResolution = resolvedAbilityInputs;
  };
  abilities = evaluation.config.aos.abilities;
  outputs = {
    network = abilities.compositionOutputs."consumer:network".resource.value;
    filesystems = abilities.compositionOutputs."consumer:filesystems".resource.value;
    milestone = abilities.compositionOutputs."consumer:milestone".resource.value;
    runtimeEntries = abilities.compositionOutputs."consumer:runtime-entries".resource.value;
  };
  resources = builtins.attrValues abilities.resolvedResources;
  resourceFor = reference:
    builtins.head (builtins.filter (resource: resource.resource == reference.resource) resources);
  network = resourceFor outputs.network;
  filesystems = resourceFor outputs.filesystems;
  milestone = resourceFor outputs.milestone;
  runtimeEntries = resourceFor outputs.runtimeEntries;
  effectsRequests = abilities.compositionRequests;
  runtimeEntryConfiguration =
    (lib.evalModules {
      inherit lib;
      modules = [
        {
          options.environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
        }
        ../../pkgs/system/_systemd-abilities/platform/runtime-entries.nix
      ];
      specialArgs.abilitySelection.bindingsForImplementation = localKey:
        lib.optional (localKey == "runtime-entry-population") {
          request.value.parameters.entries = [testRuntimeEntry];
        };
    }).config.environment.etc."tmpfiles.d/aos-runtime-entries.conf".text;
in
  assert builtins.length resources == 4;
  assert network.realization == null;
  assert filesystems.realization == null;
  assert milestone.realization == null;
  assert runtimeEntries.realization == null;
  assert network.value.scope == "configured-connectivity";
  assert filesystems.value.scope == "local-filesystems";
  assert milestone.value.milestone == "interactive-console";
  assert runtimeEntries.value.entries
  == [testRuntimeEntry];
  assert network.lifetime == "instance";
  assert milestone.lifetime == "instance";
  assert runtimeEntries.lifetime == "instance";
  assert lib.hasInfix "d /run/example 0750 root root -" runtimeEntryConfiguration;
  assert effectsRequests.${networkChild.request}.parameters
  == {
    expected = network.value;
    systemd_unit.unit_name = "network-online.target";
  };
  assert effectsRequests.${milestoneChild.request}.parameters
  == {
    expected = milestone.value;
    systemd_unit.unit_name = "getty.target";
  };
  assert effectsRequests.${runtimeEntriesChild.request}.parameters
  == {
    expected = runtimeEntries.value;
    systemd_unit.unit_name = "systemd-tmpfiles-setup.service";
  };
  assert abilities.implementations."systemd:network-readiness".handlerDescriptor == null;
  assert abilities.implementations."systemd:filesystem-readiness".handlerDescriptor == null;
  assert abilities.implementations."systemd:activation-milestone".handlerDescriptor == null;
  assert abilities.implementations."systemd:runtime-entry-population".handlerDescriptor == null;
  assert abilities.implementations."systemd:systemd-network-readiness-effects".providerModule == null;
  assert abilities.implementations."systemd:systemd-filesystem-readiness-effects".providerModule == null;
  assert abilities.implementations."systemd:systemd-activation-milestone-effects".providerModule == null;
  assert abilities.implementations."systemd:systemd-runtime-entry-population-effects".providerModule == null; true
