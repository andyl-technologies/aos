##! Filesystem-entry planning publication from the selected package provider.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  filesystemEntry = serviceManagement.interfaces.filesystemEntry;
  evaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = {
            authority = "test";
            key = "filesystem-entry";
            stage = "host";
          };
          bindings."test:entry" = {
            request = "consumer:entry";
            implementation = "aos-filesystem-provider:filesystem-entry";
            providerInstance = "aos-filesystem-provider:filesystem";
            slot = "entry";
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-filesystem-provider";
        module = {
          imports = [
            ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
            ../../pkgs/filesystem/_aos-filesystem-provider/provider.nix
          ];
          config.aos.abilities.instances.filesystem = {};
        };
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
    ];
    specialArgs = {
      inherit pkgs;
      packageName = "aos-filesystem-provider";
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
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
  true
