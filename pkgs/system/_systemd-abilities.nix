##! Package-owned systemd ability declarations and executable implementations.
{lib, ...}: let
  types = lib.abilities.types;
  artifact = lib.abilities.packageOutput {};
  handlerArtifact = lib.abilities.packageOutput {
    package = "aos-systemd-provider";
  };

  resourceReferenceList = types.list {
    element = types.deferredResult types.resourceReference;
    maxItems = 256;
  };
  dependencies = types.record {
    fields = {
      after = resourceReferenceList;
      before = resourceReferenceList;
      requires = resourceReferenceList;
      wants = resourceReferenceList;
    };
  };
  dropIn = types.record {
    fields = {
      accepted_exit_statuses = types.list {
        element = types.integer {
          minimum = 0;
          maximum = 255;
        };
        maxItems = 256;
      };
      reload_triggers = types.list {
        element = types.deferredResult types.executionPath;
        maxItems = 256;
      };
      search_path = types.list {
        element = types.artifactSelector;
        maxItems = 128;
      };
    };
  };
  packagedUnitSource = types.record {
    fields = {
      artifact = types.artifactSelector;
      unit_file = types.relativePath;
      unit_name = {
        type = types.optional (types.string {
          maxLength = 255;
          syntax = null;
        });
        optional = true;
      };
    };
  };
  realizedPackagedUnitSource = types.record {
    fields = {
      artifact = types.artifactSelector;
      unit_file = types.relativePath;
      unit_name = types.string {
        maxLength = 255;
        syntax = null;
      };
    };
  };
  packagedUnitRequest = types.record {
    fields = {
      source = packagedUnitSource;
      activation = types.enum ["enabled" "reference"];
      inherit dependencies;
      drop_in = dropIn;
    };
  };
  packagedUnitObservation = types.record {
    fields = {
      schema = types.enum ["aos.ability.systemd-packaged-unit-observation/v1"];
      expected = packagedUnitRequest;
      observed = {
        type = types.optional packagedUnitRequest;
        optional = true;
      };
      unit_name = types.string {
        maxLength = 255;
        syntax = null;
      };
      state = types.enum ["absent" "active" "failed" "inactive" "unknown"];
      discrepancies = types.list {
        element = types.localKey;
        maxItems = 128;
      };
    };
  };
  realizationType = types.record {
    fields = {
      schema = types.enum ["aos.systemd.packaged-unit-realization/v1"];
      source = realizedPackagedUnitSource;
      activation = types.enum ["enabled" "reference"];
      inherit dependencies;
      drop_in = dropIn;
    };
  };

  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = false;
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = "systemd-packaged-unit";
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  method = name: description: access: stopsProvider: retained: {
    inherit description;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    parameters = packagedUnitRequest;
    targetResource = "aos.systemd.packaged-unit";
    outputs =
      {
        observation =
          output
          (
            if name == "observe"
            then "observation"
            else "runtime"
          )
          "attempt"
          "Reports the exact packaged-unit and drop-in state."
          packagedUnitObservation;
      }
      // lib.optionalAttrs retained {
        retained-resource =
          output
          "runtime"
          "instance"
          "References the exact retained packaged-unit activation."
          types.resourceReference;
      };
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = packagedUnitObservation;
      observationEvidence = packagedUnitObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  packagedUnitDeclaration = lib.abilities.declareInterface {
    name = "aos.systemd.packaged-unit";
    description = "Activates and augments one authenticated unit shipped by a package.";
    abi = 1;
    requestType = packagedUnitRequest;
    outputs.unit-resource =
      output
      "planning"
      "instance"
      "References the exact packaged unit for logical dependency edges."
      types.resourceReference;
    methods = {
      apply =
        method
        "apply"
        "Applies the exact drop-in and activation state without replacing the packaged unit."
        "exclusive-write"
        false
        true;
      observe =
        method
        "observe"
        "Observes the exact packaged unit and any selected augmentation."
        "read"
        false
        false;
    };
    inherit lifecycle aggregation;
    configurationType = null;
    guarantees = [];
  };
in {
  config.aos.abilities = {
    interfaces.systemd-packaged-unit = packagedUnitDeclaration;

    implementations.systemd-packaged-unit = {
      description = "Activates authenticated packaged units and materializes bounded systemd drop-ins.";
      interface = "systemd-packaged-unit";
      inherit artifact;
      methods = ["apply" "observe"];
      guarantees = [];
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/systemd.nix";
      };
      handlerDescriptor = {
        artifact = handlerArtifact;
        entryPoint = "bin/aos-systemd-provider";
        arguments = packagedUnitRequest;
        result = packagedUnitObservation;
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };
  };
}
