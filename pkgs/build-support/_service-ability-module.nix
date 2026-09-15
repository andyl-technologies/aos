##! Builds a package module for a manager-neutral service implementation.
{
  lib,
  packageName,
  spec,
}: let
  inherit (lib.abilities) types;
  inherit (lib.abilities.interfaces) serviceManagement;

  defaultServices = [
    {
      key = "main";
      dependencies = [];
    }
  ];
  services = spec.services or defaultServices;
  hasDependencies = builtins.any (service: service.dependencies != []) services;
  defaultFeatures = [
    "configuration"
    "identity"
    "isolation"
    "readiness"
    "storage"
    "supervision"
  ];
  serviceSpec = {
    inherit services;
    interface = spec.interface;
    methods = spec.methods or ["observe" "restart" "start" "stop"];
    features = spec.features or (defaultFeatures ++ lib.optional hasDependencies "dependencies");
    serviceManagement = {
      inherit (serviceManagement) interface;
      features = builtins.mapAttrs (_: value: value) serviceManagement.features;
    };
  };

  restartToken = types.string {
    maxLength = 1024;
    syntax = null;
  };
  provider = (import ./_service-ability-provider/default.nix) {spec = serviceSpec;};
in {
  config.aos.abilities = lib.abilities.projectDefinitions {
    service = {
      definition = lib.abilities.define {
        interface = serviceSpec.interface;
        abi = 1;
        requestSchema = types.boolean;
        configurationSchema = types.record {
          fields = {
            enabled = types.boolean;
            restart_token = restartToken;
          };
          optional = ["restart_token"];
        };
        outputs = {};
        methods = {};
        lifecycle = serviceManagement.lifecycle;
        guarantees = [];
        aggregation = {
          scope = "provider-instance";
          key = "slot";
          rejectSlotCollisions = true;
          mergeContract = null;
          controllerGroup = "service";
        };
        requires.service-terminal = {
          inherit (serviceManagement.interface) abi descriptor;
          interface = serviceManagement.interface.name;
          inherit (serviceSpec) methods;
          guarantees = serviceManagement.featureGuarantees serviceSpec.features;
          strength = "required";
          fallback = null;
        };
        composeEntry = "compose";
        transitionEntry = "transition";
        ownsResourceKinds = [serviceManagement.interface.name];
        compose = provider.compose;
        transition = provider.transition;
      };
    };
  };
}
