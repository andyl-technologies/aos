##! D-Bus-owned system-bus registration aggregation contracts.
{lib, ...}: let
  inherit (lib.abilities) declareInterface types;

  controllerAlias = "system-registration";
  contributionAlias = "system-registration-contribution";
  resourceKind = "aos.dbus.system-registration";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  packageArtifact = lib.abilities.packageOutput {};
  artifactDirectories = types.list {
    element = types.artifactPathReference;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  baseRequest = types.record {
    fields = {
      name = types.localKey;
      stock_configuration = types.artifactPathReference;
      operator_policy_directory = types.executionPath;
      reload = serviceTypes.reload;
    };
  };
  contributionRequest = types.record {
    fields = {
      name = types.localKey;
      activation_directories = artifactDirectories;
      policy_directories = artifactDirectories;
    };
  };
  aggregateRequest = types.record {
    fields = {
      base = baseRequest;
      contributions = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 256;
        value = contributionRequest;
      };
    };
  };
  observation = types.record {
    fields = {
      schema = types.enum ["aos.ability.dbus-system-registration-observation/v1"];
      expected = aggregateRequest;
      state = types.enum ["absent" "materialized" "unknown"];
      configuration_path = {
        type = types.optional types.executionPath;
        optional = true;
      };
    };
  };
  realization = types.record {
    fields.schema = types.enum ["aos.dbus.system-registration-realization/v1"];
  };
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
  };
  method = name: description: access: stopsProvider: parameters: outputs: {
    inherit description parameters outputs;
    semantics = {
      requiredTargetAccess = access;
      inherit stopsProvider;
    };
    targetResource = resourceKind;
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observation;
      observationEvidence = observation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  controllerMethods = {
    materialize = method "materialize" "Materializes the collision-checked system-bus registration set." "exclusive-write" false aggregateRequest {
      observation = output "runtime" "attempt" "Reports the exact registration configuration state." observation;
      retained-resource = output "runtime" "instance" "References the retained registration set." types.resourceReference;
    };
    observe = method "observe" "Observes the exact system-bus registration set." "read" false aggregateRequest {
      observation = output "observation" "attempt" "Reports the exact registration configuration state." observation;
    };
    release = method "release" "Releases the materialized system-bus registration set." "exclusive-write" true aggregateRequest {
      observation = output "runtime" "attempt" "Reports absence of the released registration configuration." observation;
    };
  };
  contributionMethods = {
    observe = method "observe" "Observes the aggregate containing this package registration." "read" false contributionRequest {
      observation = output "observation" "attempt" "Reports the aggregate registration configuration state." observation;
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
    rejectSlotCollisions = false;
    mergeContract = lib.abilities.descriptorFor "aos.ability.merge-contract/v1" {
      schema = types.schemaOf "D-Bus system registration aggregate" aggregateRequest;
    };
    controllerGroup = controllerAlias;
  };
  controllerDeclaration = declareInterface {
    name = resourceKind;
    description = "Owns one system-bus configuration assembled from authorized package registrations.";
    abi = 1;
    requestType = baseRequest;
    methods = controllerMethods;
    inherit lifecycle aggregation;
    outputs.registration-resource =
      output "planning" "instance"
      "References the exact aggregate system-bus registration resource."
      types.resourceReference;
    outputs.configuration-path =
      output "planning" "instance"
      "Returns the generated system-bus configuration path."
      types.executionPath;
    outputs.configuration-resource =
      output "planning" "instance"
      "References the exact generated system-bus configuration resource."
      types.resourceReference;
    guarantees = [];
  };
  contributionDeclaration = declareInterface {
    name = "aos.dbus.system-registration-contribution";
    description = "Contributes authenticated package activation and policy directories to the system bus.";
    abi = 1;
    requestType = contributionRequest;
    methods = contributionMethods;
    lifecycle = lifecycle // {releasesEphemeralOnDisable = false;};
    inherit aggregation;
    outputs.registration-resource =
      output "planning" "instance"
      "References the aggregate system-bus registration resource."
      types.resourceReference;
    guarantees = [];
  };
in {
  config.aos.abilities = {
    interfaces = {
      ${controllerAlias} = controllerDeclaration;
      ${contributionAlias} = contributionDeclaration;
    };

    implementations = {
      ${controllerAlias} = {
        description = "Materializes one system-bus configuration assembled from authorized registrations.";
        interface = controllerAlias;
        artifact = packageArtifact;
        methods = builtins.attrNames controllerMethods;
        guarantees = [];
        requirements = {
          configuration-materialization = {
            alias = "configuration-materialization";
            description = "Materializes the assembled system-bus configuration.";
            accepted_interfaces = [serviceManagement.interfaces.managedConfiguration.identity];
            methods = ["materialize" "observe" "release"];
            guarantees = [];
            strength = "required";
            fallback = null;
          };
          service-reload = {
            alias = "service-reload";
            description = "Reloads the system bus after registration changes.";
            accepted_interfaces = [serviceManagement.interfaces.reload.identity];
            methods = ["observe" "reload"];
            guarantees = [];
            strength = "required";
            fallback = null;
          };
        };
        providerModule = {
          artifact = packageArtifact;
          path = "share/aos/providers/dbus-registration.nix";
        };
        desiredType = realization;
        requiredFeatures = [];
      };
      ${contributionAlias} = {
        description = "Merges one authenticated package registration into the system-bus configuration.";
        interface = contributionAlias;
        artifact = packageArtifact;
        methods = builtins.attrNames contributionMethods;
        guarantees = [];
        providerModule = {
          artifact = packageArtifact;
          path = "share/aos/providers/dbus-registration.nix";
        };
        desiredType = realization;
        requiredFeatures = [];
      };
    };
  };
}
