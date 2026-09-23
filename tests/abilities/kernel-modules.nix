##! Checks the kmod-owned kernel-module provider through the standard fixed point.
{
  lib,
  pkgs,
}: let
  selectedProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.kmod;
    implementation = "kernel-modules";
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelModules = serviceManagement.interfaces.kernelModules;
  request = serviceManagement.forProducer {
    consumerInstance = "workload";
    key = "required-modules";
    interface = kernelModules;
    parameters = {
      modules = ["zeta" "overlay"];
      required = true;
    };
  };
  childRequestKey = lib.abilities.compositionRequestKey {
    implementation = "kmod:kernel-modules";
    providerInstance = "kmod:manager";
    key = "required-modules";
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
              key = "kernel-modules";
              stage = "host";
            };
            instances."kmod:manager" = {};
            bindings =
              {
                "test:kernel-modules" = {
                  request = "consumer:required-modules";
                  implementation = "kmod:kernel-modules";
                  providerInstance = "kmod:manager";
                  slot = "required-modules";
                };
              }
              // lib.optionalAttrs includeEffects {
                "test:kernel-module-effects" = {
                  request = childRequestKey;
                  implementation = "kmod:kernel-module-effects";
                  providerInstance = "kmod:manager";
                  slot = "required-modules";
                };
              };
          };
        }
      ];
      packageModules = [
        {
          name = "kmod";
          inherit (pkgs.kmod) version;
          module = pkgs.kmod.module + "/module.nix";
        }
        {
          name = "consumer";
          module.imports = [
            {config.aos.abilities.instances.workload = {};}
            {config.aos.abilities = request;}
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
  output = abilities.compositionOutputs."consumer:required-modules".resource;
  transition = abilities.implementations."kmod:kernel-modules".transition;
  effectsInterface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration abilities.interfaces."kmod:kernel-module-effects"
  );
  transitionMethods = kind: let
    active = builtins.elem kind ["create" "update" "reconcile-stopped" "reconcile-divergent"];
    binding = {
      id = "kernel-module-effects";
      request.consumer = desired.resource.provider;
      interface = effectsInterface;
      caller_grant = {
        methods = ["load" "observe"];
        resources = [
          {
            resource = desired.resource;
            access = "exclusive-write";
            operations = ["load"];
          }
        ];
      };
    };
    fragment = transition {
      provider = desired.resource.provider;
      operation_scope = ["kernel-modules"];
      changes = [
        {
          inherit kind;
          resource = desired.resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings = lib.optional active {
        authority.role = "desired";
        inherit binding;
      };
      controllers = lib.optional active {
        resource = desired.resource;
        controller = {
          provider = desired.resource.provider;
          group = "kernel-modules";
        };
      };
    };
  in
    builtins.map (operation: operation.method) fragment.operations;
in
  assert builtins.removeAttrs abilities.interfaces.${kernelModules.alias} ["localKey" "package"]
  == kernelModules.declaration;
  assert !(abilities.interfaces ? "kmod:kernel-modules");
  assert builtins.attrNames abilities.implementations
  == [
    "kmod:kernel-module-effects"
    "kmod:kernel-modules"
  ];
  assert abilities.compositionRequests.${childRequestKey}.parameters == desired.value;
  assert desired.kind == kernelModules.identity.name;
  assert desired.lifetime == "persistent";
  assert desired.value
  == {
    modules = ["overlay" "zeta"];
    required = true;
  };
  assert desired.realization
  == {
    schema = "aos.kmod.module-set-realization/v1";
    modules = ["overlay" "zeta"];
    required = true;
  };
  assert output.value.resource == desired.resource;
  assert output.value.operations == ["observe"];
  assert output.phase == "planning";
  assert output.lifetime == "persistent";
  assert transitionMethods "create" == ["load"];
  assert transitionMethods "update" == ["load"];
  assert transitionMethods "reconcile-stopped" == ["load"];
  assert transitionMethods "reconcile-divergent" == ["load"];
  assert transitionMethods "unchanged" == [];
  assert transitionMethods "remove" == []; true
