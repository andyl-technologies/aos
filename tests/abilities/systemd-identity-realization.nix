##! Fixed-point realization of a managed identity through the systemd provider.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  groupInterface = serviceManagement.interfaces.groupResolution;
  effectsRequestKey = lib.abilities.compositionRequestKey {
    implementation = "systemd:group-resolution";
    providerInstance = "systemd:manager";
    key = "operators";
  };
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "group-resolution";
  };
  evaluation = lib.evalModules {
    inherit lib;
    modules =
      ([
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "systemd-identity";
            stage = "host";
          };
          bindings = {
            "test:group" = {
              request = "consumer:group";
              implementation = "systemd:group-resolution";
              providerInstance = "systemd:manager";
              slot = "operators";
            };
            "test:group-effects" = {
              request = effectsRequestKey;
              implementation = "systemd:systemd-group-effects";
              providerInstance = "systemd:manager";
              slot = "operators";
            };
          };
          instances."systemd:manager" = {};
        };
      }
    ])
      ++ builtins.map lib.authenticatedModule (([
      {
        name = "systemd";
        inherit (pkgs.systemd) version;
        module = pkgs.systemd.module + "/module.nix";
      }
      {
        name = "consumer";
        module.config.aos.abilities = {
          instances.identity-client = {};
          requirementTemplates.group = {
            interface = groupInterface.identity.name;
            inherit (groupInterface.identity) abi descriptor;
            methods = groupInterface.methods;
            guarantees = [];
            strength = "required";
            fallback = null;
          };
          requests.group = {
            requirement = "group";
            consumer = "identity-client";
            scope = ["operators"];
            parameters = {
              name = "operators";
              allocation = "managed";
            };
          };
        };
      }
    ]) ++ ([selectedSystemdProvider]));


    specialArgs = {
      inherit pkgs;
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  resources = builtins.attrValues evaluation.config.aos.abilities.desiredResources;
  resource = builtins.head resources;
  request = evaluation.config.aos.abilities.compositionRequests.${effectsRequestKey};
  outputs = evaluation.config.aos.abilities.compositionOutputs."consumer:group";
  controller = evaluation.config.aos.abilities.implementations."systemd:group-resolution";
  terminal = evaluation.config.aos.abilities.implementations."systemd:systemd-group-effects";
in
  assert builtins.length resources == 1;
  assert resource.kind == "aos.identity.group";
  assert resource.value.name == "operators";
  assert resource.realization
  == {
    schema = "aos.systemd.identity-realization/v1";
    backend = "systemd-sysusers";
  };
  assert request.parameters.desired == resource.value;
  assert outputs.group-name.value == "operators";
  assert controller.handlerDescriptor == null;
  assert builtins.isFunction controller.transition;
  assert terminal.providerModule == null;
  assert terminal.handlerDescriptor.entryPoint == "bin/aos-systemd-group-effects"; true
