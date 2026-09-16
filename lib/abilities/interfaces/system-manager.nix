##! Provider-neutral system manager selection interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  declaration = declareInterface {
    name = "aos.system.manager";
    abi = 1;
    description = "Selects the package that realizes system and initrd manager artifacts.";
    requestType = types.boolean;
    outputs.selected-manager = {
      phase = "planning";
      lifetime = "persistent";
      visibility = "protected";
      description = "References the authenticated package selected to realize manager artifacts.";
      schema = types.artifactReference;
    };
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "system-manager";
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
  manager = {
    alias = "system-manager";
    name = declaration.name;
    inherit declaration document;
    identity = interfaceIdentity document;
  };
  libraryView = {
    interfaces = {inherit manager;};
    declarations.${manager.alias} = manager.declaration;
  };
in {
  name = "systemManager";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
