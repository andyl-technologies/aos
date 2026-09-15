##! Canonical manager-neutral service and runtime-input ability declarations.
{
  types,
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  serviceTypes = import ./_service-types.nix {
    inherit types;
  };
  interfaces = import ./_service-interfaces.nix {
    inherit
      declareInterface
      descriptorFor
      interfaceDocumentFromDeclaration
      interfaceIdentity
      serviceTypes
      ;
  };
  constructors = import ./_service-declaration.nix {
    serviceInterfaces = interfaces;
  };
in {
  types = serviceTypes;
  inherit interfaces;
  declarations = builtins.listToAttrs (builtins.map (value: {
      name = value.alias;
      value = value.declaration;
    })
    (builtins.attrValues interfaces));
  inherit (constructors) featureInterfaces forConfiguration forProducer forService structuredSource validate;
}
