##! Checks the provider-owned kernel-tunable implementation through the fixed point.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.aos-kernel-tunable-provider;
    implementation = "kernel-tunables";
  };
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "aos-kernel-tunable-provider:kernel-tunables";
    providerInstance = "aos-kernel-tunable-provider:manager";
    key = "network-forwarding";
  };
  evaluate = {
    includeEffects,
    abilityResolution,
  }:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities = {
            environment = {
              authority = "test";
              key = "kernel-tunables";
              stage = "host";
            };
            instances."aos-kernel-tunable-provider:manager" = {};
            bindings =
              {
                "test:kernel-tunables" = {
                  request = "consumer:network-forwarding";
                  implementation = "aos-kernel-tunable-provider:kernel-tunables";
                  providerInstance = "aos-kernel-tunable-provider:manager";
                  slot = "network-forwarding";
                };
              }
              // lib.optionalAttrs includeEffects {
                "test:kernel-tunable-effects" = {
                  request = childRequestKey;
                  implementation = "aos-kernel-tunable-provider:kernel-tunable-effects";
                  providerInstance = "aos-kernel-tunable-provider:manager";
                  slot = "network-forwarding";
                };
              };
          };
        }
      ];
      packageModules = [
        {
          name = "aos-kernel-tunable-provider";
          inherit (pkgs.aos-kernel-tunable-provider) version;
          module = pkgs.aos-kernel-tunable-provider.module + "/module.nix";
        }
        {
          name = "consumer";
          module.imports = [
            {
              config.aos.abilities = lib.abilities.interfaces.serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "network-forwarding";
                interface = {
                  alias = "kernel-tunables";
                  declaration = lib.abilities.interfaces.kernelTunables.interface.declaration;
                };
                methods = ["apply" "observe" "remove"];
                parameters = {
                  values = {
                    "net.bridge.bridge-nf-call-iptables" = "1";
                    "net.ipv4.ip_forward" = "1";
                  };
                  dependencies = [];
                };
              };
            }
            {config.aos.abilities.instances.workload = {};}
          ];
        }
      ];
      selectedProviderModules = [selectedProvider];
      specialArgs = {inherit abilityResolution;};
    };
  initial = evaluate {
    includeEffects = false;
    abilityResolution = {
      requests = {};
      requirements = {};
    };
  };
  evaluated = evaluate {
    includeEffects = true;
    abilityResolution = import ./_composition-resolution.nix {
      abilities = initial.config.aos.abilities;
      requestKeys = [childRequestKey];
    };
  };
  abilities = evaluated.config.aos.abilities;
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  output = abilities.compositionOutputs."consumer:network-forwarding".resource;
  transition = abilities.implementations."aos-kernel-tunable-provider:kernel-tunables".transition;
  effectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration abilities.interfaces."aos-kernel-tunable-provider:kernel-tunable-effects"
  );
  transitionMethods = kind: let
    method =
      if kind == "remove"
      then "remove"
      else if kind == "unchanged"
      then null
      else "apply";
    binding = {
      id = "kernel-tunable-effects";
      request.consumer = desired.resource.provider;
      interface = effectsInterface;
      caller_grant = {
        methods = ["apply" "observe" "remove"];
        resources = lib.optional (method != null) {
          resource = desired.resource;
          access = "exclusive-write";
          operations = [method];
        };
      };
    };
    fragment = transition {
      provider = desired.resource.provider;
      operation_scope = ["kernel-tunables"];
      changes = [
        {
          inherit kind;
          resource = desired.resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings = lib.optional (method != null) {
        authority =
          if kind == "remove"
          then {
            role = "teardown";
            source_request.consumer = desired.resource.provider;
          }
          else {role = "desired";};
        inherit binding;
      };
      controllers = lib.optional (method != null) {
        resource = desired.resource;
        controller = {
          provider = desired.resource.provider;
          group = "kernel-tunables";
        };
      };
    };
  in
    builtins.map (operation: operation.method) fragment.operations;
in
  assert abilities.interfaces ? "kernel-tunables";
  assert builtins.attrNames abilities.implementations
  == [
    "aos-kernel-tunable-provider:kernel-tunable-effects"
    "aos-kernel-tunable-provider:kernel-tunables"
  ];
  assert abilities.compositionRequests.${childRequestKey}.parameters == desired.value;
  assert desired.kind == "aos.kernel.tunables";
  assert desired.lifetime == "instance";
  assert desired.value.values
  == {
    "net.bridge.bridge-nf-call-iptables" = "1";
    "net.ipv4.ip_forward" = "1";
  };
  assert desired.value.dependencies == [];
  assert desired.realization == {schema = "aos.kernel.tunables-realization/v1";};
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert output.phase == "planning";
  assert output.lifetime == "instance";
  assert transitionMethods "create" == ["apply"];
  assert transitionMethods "update" == ["apply"];
  assert transitionMethods "reconcile-stopped" == ["apply"];
  assert transitionMethods "reconcile-divergent" == ["apply"];
  assert transitionMethods "unchanged" == [];
  assert transitionMethods "remove" == ["remove"]; true
