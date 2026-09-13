##! Shared package contract for manager-neutral service lifecycle.
{
  lib,
  packageName,
}: let
  inherit (lib.abilities) schemas;

  serviceManagement = import ./service-management.nix {
    inherit schemas;
    inherit (lib.abilities) guarantee;
  };

  catalog = import ./providers/service-package/catalog.nix;
  spec =
    catalog.${packageName}
    or (throw "service ability package has no catalog entry for '${packageName}'");
  providerArtifact = ./providers/service-package;

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
  provider = import providerArtifact;
in {
  activationMode = "structured-effects";
  requiredFeatures = ["abilities-v1"];
  ownership = [[]];
  artifacts = [];
  requirements = {};

  exports.service = {
    artifact = providerArtifact;
    export = lib.abilities.define {
      interface = spec.interface;
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
        inherit (spec) methods;
        guarantees = serviceManagement.featureGuarantees spec.features;
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
