##! Provider-neutral immutable image construction interface.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  declaration = declareInterface {
    name = "aos.image.builder";
    abi = 1;
    description = "Selects one package-owned immutable image builder.";
    requestType = types.boolean;
    outputs.builder-artifact = {
      phase = "planning";
      lifetime = "instance";
      visibility = "protected";
      description = "References the package that produces the selected immutable image plan.";
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
      controllerGroup = "image-builder";
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
  builder = {
    alias = "image-builder";
    name = declaration.name;
    inherit declaration document;
    identity = interfaceIdentity document;
  };
  libraryView = {
    interfaces = {inherit builder;};
    declarations.${builder.alias} = builder.declaration;
  };
in {
  name = "imageBuilder";
  readView = libraryView;
  module.config.aos.abilities.interfaces = libraryView.declarations;
}
