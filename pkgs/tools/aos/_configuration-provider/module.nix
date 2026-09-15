##! Native provider declaration for typed configuration materialization.
{lib, ...}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interface = serviceManagement.interfaces.managedConfiguration;
  abilityTypes = lib.abilities.types;
  runtimeArtifact = lib.abilities.packageOutput {output = "packageRuntime";};
  realizationType = abilityTypes.record {
    fields = {
      schema = abilityTypes.enum ["aos.configuration.materializer-realization/v1"];
      path = serviceManagement.types.executionPath;
    };
  };
in {
  config.aos.abilities = {
    interfaces.configuration-materialization = interface.declaration;
    implementations.configuration-materialization = {
      description = "Materializes typed configuration through the AOS configuration provider.";
      interface = "configuration-materialization";
      artifact = runtimeArtifact;
      inherit (interface) methods;
      guarantees = [];
      providerModule = {
        artifact = runtimeArtifact;
        path = "share/aos/providers/configuration-materialization.nix";
      };
      handlerDescriptor = {
        artifact = runtimeArtifact;
        entryPoint = "libexec/aos-configuration-provider";
        arguments = interface.requestType;
        result = interface.observationType;
      };
      desiredType = realizationType;
      requiredFeatures = [];
    };
  };
}
