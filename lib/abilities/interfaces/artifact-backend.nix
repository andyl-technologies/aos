##! Provider-neutral artifact construction backend selection.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  declaration = declareInterface {
    name = "aos.artifacts.backend";
    abi = 1;
    description = "Selects one authenticated package-owned artifact construction backend.";
    requestType = types.boolean;
    outputs.artifact-reference = {
      schema = types.artifactReference;
      phase = "planning";
      lifetime = "persistent";
      visibility = "protected";
      description = "Identifies the exact selected backend package output.";
    };
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "artifact-backend";
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
  backend = {
    alias = "artifact-backend";
    name = declaration.name;
    inherit declaration document;
    identity = interfaceIdentity document;
  };
  libraryView = {
    interfaces = {inherit backend;};
    declarations.${backend.alias} = backend.declaration;
  };
in {
  name = "artifactBackend";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
