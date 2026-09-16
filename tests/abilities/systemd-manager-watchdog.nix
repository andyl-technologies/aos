##! Pure controller and terminal manager-watchdog composition.
{
  lib,
  pkgs,
}: let
  controllerName = "systemd:systemd-manager-watchdog";
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "systemd-manager-watchdog";
  };
  baseBindings = {
    "test:watchdog" = {
      request = "consumer:watchdog";
      implementation = controllerName;
      providerInstance = "systemd:manager";
      slot = "watchdog";
    };
  };
  consumer = {config, ...}: let
    serviceManagement = lib.abilities.interfaces.serviceManagement;
    request = serviceManagement.forProducer {
      consumerInstance = "application";
      key = "watchdog";
      interface = {
        alias = "watchdog";
        declaration = config.aos.abilities.interfaces.${controllerName};
      };
      methods = ["apply" "observe" "remove"];
      parameters = {
        enabled = true;
        runtime_timeout_millis = 30000;
        reboot_timeout_millis = 60000;
        kexec_timeout_millis = 60000;
      };
    };
    contribution = serviceManagement.splitContribution request;
  in {
    config.aos.abilities = lib.mkMerge [
      {instances.application = {};}
      contribution.declarations
      contribution.configured
    ];
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-manager-watchdog";
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
          module = consumer;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  pending = evaluate baseBindings;
  child = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolved = evaluate (baseBindings
    // {
      "test:watchdog-effects" = {
        request = child.request;
        implementation = "systemd:systemd-manager-watchdog-effects";
        providerInstance = "systemd:manager";
        slot = child.slot;
      };
    });
  abilities = resolved.config.aos.abilities;
  resource = builtins.head (builtins.attrValues abilities.desiredResources);
  controller = abilities.implementations.${controllerName};
  terminal = abilities.implementations."systemd:systemd-manager-watchdog-effects";
in
  assert child.requirement == "manager-watchdog-effects";
  assert abilities.compositionPendingRequests == {};
  assert resource.value.enabled;
  assert resource.realization
  == {
    schema = "aos.systemd.manager-watchdog-realization/v1";
    enabled = true;
    runtime_timeout_millis = 30000;
    reboot_timeout_millis = 60000;
    kexec_timeout_millis = 60000;
  };
  assert builtins.isFunction controller.transition;
  assert controller.handlerDescriptor == null;
  assert terminal.providerModule == null;
  assert terminal.handlerDescriptor.entryPoint == "libexec/aos-systemd-provider";
  assert builtins.length resolved.config.systemd.providerManagerConfigurationPlans == 1; true
