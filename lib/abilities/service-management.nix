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
  interfaceCatalog = import ./_service-interfaces.nix {
    inherit
      declareInterface
      descriptorFor
      interfaceDocumentFromDeclaration
      interfaceIdentity
      serviceTypes
      ;
  };
  inherit (interfaceCatalog) interfaces;
  constructors = import ./_service-declaration.nix {
    inherit interfaceDocumentFromDeclaration interfaceIdentity;
    serviceInterfaces = interfaces;
  };
  moduleDeclaration = interface:
    interface.declaration
    // {
      guarantees = interface.guarantees or [];
      methods = builtins.mapAttrs (_: method:
        method
        // {
          guarantees = builtins.map interfaceCatalog.guaranteeAliasFor method.guarantees;
        })
      interface.declaration.methods;
    };
in {
  types = serviceTypes;
  inherit (interfaceCatalog) guaranteeAliases guaranteeDeclarations;
  inherit interfaces;
  declarations = builtins.listToAttrs (builtins.map (value: {
      name = value.alias;
      value = value.declaration;
    })
    (builtins.attrValues interfaces));
  moduleDeclarations = builtins.listToAttrs (builtins.map (interface: {
      name = interface.alias;
      value = moduleDeclaration interface;
    })
    (builtins.attrValues interfaces));
  guarantees = interfaceCatalog.guaranteeDeclarations;
  inherit (constructors) featureInterfaces forConfiguration forProducer forProducers forService instanceOf splitContribution structuredSource validate;
}
