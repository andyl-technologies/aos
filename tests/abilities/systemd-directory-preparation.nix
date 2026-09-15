##! Recursive directory preparation for systemd-managed services.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "service-lifecycle";
  };
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
          artifact = lib.abilities.packageOutput {package = "consumer";};
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
              key = "systemd-directory-preparation";
              stage = "host";
            };
            instances."systemd:manager" = {};
            inherit bindings;
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
          module = consumerModule;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        artifactLocatorFor = _: throw "directory preparation fixture does not resolve artifacts";
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pendingEvaluation = evaluate baseBindings;
  pendingRequests = pendingEvaluation.config.aos.abilities.compositionPendingRequests;
  pendingChildren = builtins.attrValues pendingRequests;
  directoryChildren =
    builtins.filter
    (candidate: candidate.requirement == "directory-preparation")
    pendingChildren;
  child = builtins.head (builtins.filter
    (candidate: candidate.implementation == "systemd:service-lifecycle")
    directoryChildren);
  effectsChild = builtins.head (builtins.filter
    (candidate: candidate.requirement == "service-effects")
    pendingChildren);
  directoryOwners = builtins.sort builtins.lessThan (builtins.map
    (candidate: candidate.implementation)
    directoryChildren);
in
  assert directoryChildren != [];
  assert lib.unique (builtins.map (candidate: candidate.requirement) pendingChildren)
  == ["directory-preparation" "service-effects"];
  assert directoryOwners == ["systemd:service-directories" "systemd:service-lifecycle"];
  assert effectsChild.implementation == "systemd:service-lifecycle";
  assert child.declaration.parameters.destination == "/var/lib/prepared/data";
  assert child.declaration.parameters.owner == "data-owner";
  assert child.declaration.parameters.group == "data-group";
  assert child.declaration.parameters.entry.kind == "directory"; true
