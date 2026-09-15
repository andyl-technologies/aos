##! Recursive directory preparation for systemd-managed services.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  requirement = selected: methods: {
    interface = selected.identity.name;
    inherit (selected.identity) abi descriptor;
    inherit methods;
    guarantees = [];
    strength = "required";
    fallback = null;
  };
  lifecycleRequest = {
    service = "prepared";
    enabled = true;
    description = "Service with an independently owned directory";
    execution_model = "foreground";
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [
      {
        executable = {
          artifact = lib.abilities.packageOutput {};
          entry_point = "bin/prepared";
          arguments = [];
        };
        ignore_failure = false;
      }
    ];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "on-failure";
    restart_delay_millis = 1000;
    remain_after_exit = false;
    start_timeout_millis = 30000;
    stop_timeout_millis = 30000;
  };
  consumerModule = {
    config.aos.abilities = {
      instances.application = {};
      requirementTemplates = {
        lifecycle = requirement interfaces.lifecycle ["observe" "start" "stop"];
        directories = requirement interfaces.directories ["observe"];
      };
      requests = {
        lifecycle = {
          requirement = "lifecycle";
          consumer = "application";
          scope = ["prepared"];
          parameters = lifecycleRequest;
        };
        directories = {
          requirement = "directories";
          consumer = "application";
          scope = ["prepared"];
          parameters = {
            service = "prepared";
            enabled = true;
            managed = [
              {
                purpose = "state";
                path = "prepared/data";
                mode = "0750";
                retention = "persistent";
                owner = "data-owner";
                group = "data-group";
              }
            ];
          };
        };
      };
    };
  };
  baseBindings = {
    "test:lifecycle" = {
      request = "consumer:lifecycle";
      implementation = "systemd:service-lifecycle";
      providerInstance = "systemd:manager";
      slot = "prepared";
    };
    "test:directories" = {
      request = "consumer:directories";
      implementation = "systemd:service-directories";
      providerInstance = "systemd:manager";
      slot = "prepared";
    };
  };
  evaluate = {
    bindings,
    includeFilesystemProvider,
  }:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-directory-preparation";
              stage = "host";
            };
            inherit bindings;
          };
        }
      ];
      packageModules =
        [
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
            module = consumerModule;
          }
        ]
        ++ lib.optional includeFilesystemProvider {
          name = "aos-filesystem-provider";
          module = {
            imports = [
              ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
              ../../pkgs/filesystem/_aos-filesystem-provider/provider.nix
            ];
            config.aos.abilities.instances.filesystem = {};
          };
        };
      specialArgs = {
        inherit pkgs;
        packageName = "systemd";
        artifactLocatorFor = _: throw "directory preparation fixture does not resolve artifacts";
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pendingEvaluation = evaluate {
    bindings = baseBindings;
    includeFilesystemProvider = false;
  };
  pendingRequests = pendingEvaluation.config.aos.abilities.compositionPendingRequests;
  pendingChildren = builtins.attrValues pendingRequests;
  child = builtins.head (builtins.filter
    (candidate: candidate.requirement == "directory-preparation")
    pendingChildren);
  effectsChild = builtins.head (builtins.filter
    (candidate: candidate.requirement == "service-effects")
    pendingChildren);
  childRequestKey = child.request;
  resolvedEvaluation = evaluate {
    includeFilesystemProvider = true;
    bindings =
      baseBindings
      // {
        "test:directory-preparation" = {
          request = childRequestKey;
          implementation = "aos-filesystem-provider:filesystem-entry";
          providerInstance = "aos-filesystem-provider:filesystem";
          slot = child.slot;
        };
        "test:service-effects" = {
          request = effectsChild.request;
          implementation = "systemd:systemd-service-effects";
          providerInstance = "systemd:manager";
          slot = effectsChild.slot;
        };
      };
  };
  abilities = resolvedEvaluation.config.aos.abilities;
  serviceResource = builtins.head (builtins.filter
    (resource: resource.kind == "aos.service.instance")
    (builtins.attrValues abilities.desiredResources));
  childOutput = abilities.compositionOutputs.${childRequestKey}.entry-resource;
  serviceSection = builtins.head (
    builtins.filter
    (section: section.name == "Service")
    (builtins.head serviceResource.realization.units).sections
  );
in
  assert builtins.length (builtins.attrNames pendingRequests) == 2;
  assert child.declaration.parameters.destination == "/var/lib/prepared/data";
  assert child.declaration.parameters.owner == "data-owner";
  assert child.declaration.parameters.group == "data-group";
  assert abilities.compositionPendingRequests == {};
  assert childOutput.value._type == "aos-resource-reference";
  assert serviceResource.realization.prerequisites == [childOutput.value];
  assert !(builtins.any (directive: directive.name == "StateDirectory") serviceSection.directives); true
