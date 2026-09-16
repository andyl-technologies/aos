##! Provider-neutral kernel platform selection interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  declaration = declareInterface {
    name = "aos.platform.kernel";
    abi = 1;
    description = "Selects the package that supplies the target kernel artifacts.";
    requestType = types.boolean;
    outputs.selected-kernel = {
      phase = "planning";
      lifetime = "persistent";
      visibility = "protected";
      description = "References the authenticated package selected to supply kernel artifacts.";
      schema = types.artifactSelector;
    };
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "kernel-platform";
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
  kernel = {
    alias = "kernel-platform";
    name = declaration.name;
    inherit declaration document;
    identity = interfaceIdentity document;
  };
  libraryView = {
    interfaces = {inherit kernel;};
    declarations.${kernel.alias} = kernel.declaration;
  };
in {
  name = "kernelPlatform";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
