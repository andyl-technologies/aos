##! D-Bus-owned system-bus registration aggregation contracts.
{lib, ...}: let
  inherit (lib.abilities) declareInterface types;

  controllerAlias = "system-registration";
  registrationSourceAlias = "system-registration-source";
  resourceKind = "aos.dbus.system-registration";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  packageArtifact = lib.abilities.packageOutput {};
  moduleArtifact = lib.abilities.packageOutput {output = "module";};
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
    };
  };
  registrationSourceRequest = types.record {
    fields = {
      name = types.localKey;
      activation_directories = artifactDirectories;
      policy_directories = artifactDirectories;
    };
  };
  aggregateRequest = types.record {
    fields = {
      base = baseRequest;
      registrations = types.map {
        keyMaxLength = 64;
        keySyntax = "local-key-v1";
        maxEntries = 256;
        value = registrationSourceRequest;
      };
    };
    optional = ["registrations"];
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
  registrationSourceMethods = {
    observe = method "observe" "Observes the aggregate containing this package registration." "read" false registrationSourceRequest {
      observation = output "observation" "attempt" "Reports the aggregate registration configuration state." observation;
    };
  };
  lifecycle = {
    persistentDeleteMethod = null;
  };
  aggregation = {
    scope = "provider-instance";
    key = "system-bus";
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
    outputs.resource =
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
  registrationSourceDeclaration = declareInterface {
    name = "aos.dbus.system-registration-source";
    description = "Provides authenticated package activation and policy directories to the system bus.";
    abi = 1;
    requestType = registrationSourceRequest;
    methods = registrationSourceMethods;
    inherit lifecycle;
    inherit aggregation;
    outputs.resource =
      output "planning" "instance"
      "References the aggregate system-bus registration resource."
      types.resourceReference;
    guarantees = [];
  };
in {
  config.aos.abilities = {
    interfaces = {
      ${controllerAlias} = controllerDeclaration;
      ${registrationSourceAlias} = registrationSourceDeclaration;
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
        };
        providerModule = {
          artifact = moduleArtifact;
          path = "registration-provider.nix";
        };
        compositionType = aggregateRequest;
        desiredType = realization;
        requiredFeatures = [];
      };
      ${registrationSourceAlias} = {
        description = "Merges one authenticated package registration into the system-bus configuration.";
        interface = registrationSourceAlias;
        artifact = packageArtifact;
        methods = builtins.attrNames registrationSourceMethods;
        guarantees = [];
        providerModule = {
          artifact = moduleArtifact;
          path = "registration-provider.nix";
        };
        desiredType = realization;
        requiredFeatures = [];
      };
    };
  };
}
