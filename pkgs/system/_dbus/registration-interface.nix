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
  output = phase: lifetime: description: schema: {
    inherit phase lifetime description schema;
    visibility = "protected";
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
    description = "Composes one system-bus configuration from authorized package registrations.";
    abi = 1;
    requestType = baseRequest;
    inherit lifecycle aggregation;
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
    inherit lifecycle;
    inherit aggregation;
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
        description = "Composes one system-bus configuration from authorized registrations.";
        interface = controllerAlias;
        artifact = packageArtifact;
        methods = [];
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
        desiredType = null;
        requiredFeatures = [];
      };
      ${registrationSourceAlias} = {
        description = "Merges one authenticated package registration into the system-bus configuration.";
        interface = registrationSourceAlias;
        artifact = packageArtifact;
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = moduleArtifact;
          path = "registration-provider.nix";
        };
        desiredType = null;
        requiredFeatures = [];
      };
    };
  };
}
