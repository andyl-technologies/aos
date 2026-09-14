##! Shared package contract for manager-neutral service lifecycle.
{
  lib,
  packageName,
  spec,
  writeTextFile,
}: let
  inherit (lib.abilities) schemas;

  serviceManagement = import ./service-management.nix {
    inherit schemas;
    inherit (lib.abilities) guarantee;
  };

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
  };

  providerSourcePath = ./providers/service-package/default.nix;
  providerSource = builtins.readFile providerSourcePath;
  providerArtifact = writeTextFile {
    name = "${packageName}-service-ability-provider";
    destination = "/default.nix";
    text = ''
      let
        makeProvider = (
          ${providerSource}
        );
        spec = builtins.fromJSON ${builtins.toJSON (builtins.toJSON serviceSpec)};
      in
        makeProvider {inherit spec;}
    '';
  };

  revision = schemas.string {
    maxLength = 71;
    syntax = null;
  };
  restartToken = schemas.string {
    maxLength = 1024;
    syntax = null;
  };
  revisionInputs = schemas.list {
    element = revision;
    maxItems = 64;
  };
  provider = (import providerSourcePath) {spec = serviceSpec;};
in {
  activationMode = "structured-effects";
  requiredFeatures = ["abilities-v1"];
  ownership = [[]];
  artifacts = [];
  requirements = {};

  exports.service = {
    artifact = providerArtifact;
    export = lib.abilities.define {
      interface = serviceSpec.interface;
      abi = 1;
      requestSchema = schemas.boolean;
      configurationSchema = schemas.record {
        fields = {
          enabled = schemas.boolean;
          inherit revision;
          restart_token = restartToken;
          revision_inputs = revisionInputs;
        };
        optional = ["restart_token" "revision" "revision_inputs"];
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
}
