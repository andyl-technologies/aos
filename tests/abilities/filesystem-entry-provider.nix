##! Filesystem-entry planning publication from the selected package provider.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-filesystem-provider;
    implementation = "filesystem-entry";
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  filesystemEntry = serviceManagement.interfaces.filesystemEntry;
  baseBindings = {
    "test:entry" = {
      request = "consumer:entry";
      implementation = "aos-filesystem-provider:filesystem-entry";
      providerInstance = "aos-filesystem-provider:filesystem";
      slot = "entry";
    };
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "filesystem-entry";
              stage = "host";
            };
            instances."aos-filesystem-provider:filesystem" = {};
            inherit bindings;
          };
        }
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "aos-filesystem-provider";
          inherit (pkgs.aos-filesystem-provider) version;
          module = pkgs.aos-filesystem-provider.module + "/module.nix";
        }
        {
          name = "consumer";
          module.config.aos.abilities = {
            instances.application = {};
            requirementTemplates.entry = {
              interface = filesystemEntry.identity.name;
              inherit (filesystemEntry.identity) abi descriptor;
              methods = ["materialize" "observe" "release"];
              guarantees = [];
              strength = "required";
              fallback = null;
            };
            requests.entry = {
              requirement = "entry";
              consumer = "application";
              scope = ["filesystem"];
              parameters = {
                name = "runtime-root";
                entry.kind = "directory";
                destination = "/run/example";
                mode = "0750";
                prerequisites = [];
              };
            };
          };
        }
      ]) ++ ([selectedProvider]));


      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pending = evaluate baseBindings;
  effectsChild = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  evaluation = evaluate (baseBindings
    // {
      "test:entry-effects" = {
        request = effectsChild.request;
        implementation = "aos-filesystem-provider:filesystem-entry-effects";
        providerInstance = "aos-filesystem-provider:filesystem";
        slot = effectsChild.slot;
      };
    });
  abilities = evaluation.config.aos.abilities;
  output = abilities.compositionOutputs."consumer:entry".entry-resource;
  resources = builtins.attrValues abilities.resolvedResources;
  resource = builtins.head (builtins.filter (candidate:
    candidate.resource == output.value.resource)
  resources);
in
  assert output.phase == "planning";
  assert output.visibility == "protected";
  assert output.lifetime == "instance";
  assert output.value._type == "aos-resource-reference";
  assert output.value.interface == filesystemEntry.identity;
  assert output.value.resource == resource.resource;
  assert output.value.operations == ["observe"];
  assert resource.value.destination == "/run/example";
  assert resource.realization.path == "/run/example";
  assert abilities.implementations."aos-filesystem-provider:filesystem-entry".handlerDescriptor == null;
  assert abilities.implementations."aos-filesystem-provider:filesystem-entry-effects".providerModule == null;
  assert abilities.implementations."aos-filesystem-provider:filesystem-entry-effects".handlerDescriptor.entryPoint
  == "libexec/aos-filesystem-entry-effects";
  assert abilities.implementations."aos-filesystem-provider:storage-allocation-effects".handlerDescriptor.entryPoint
  == "libexec/aos-storage-allocation-effects";
  assert abilities.implementations."aos-filesystem-provider:persistent-storage-allocation-effects".handlerDescriptor.entryPoint
  == "libexec/aos-persistent-storage-allocation-effects";
  assert abilities.implementations."aos-filesystem-provider:storage-view-effects".handlerDescriptor.entryPoint
  == "libexec/aos-storage-view-effects"; true
