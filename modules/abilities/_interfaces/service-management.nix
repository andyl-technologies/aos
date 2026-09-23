##! Canonical manager-neutral service and runtime-input ability declarations.
{
  types,
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  serviceTypes = import ../_service-types.nix {
    inherit types;
  };
  interfaceCatalog = import ../_service-interfaces.nix {
    inherit
      declareInterface
      descriptorFor
      interfaceDocumentFromDeclaration
      interfaceIdentity
      serviceTypes
      ;
  };
  inherit (interfaceCatalog) interfaces;
  constructors = import ../_service-declaration.nix {
    inherit interfaceDocumentFromDeclaration interfaceIdentity;
    inherit serviceTypes;
    serviceInterfaces = interfaces;
  };
  projectService = import ../_service-projection.nix {
    serviceManagement = readView;
  };
  projectContributions = import ../_contribution-projection.nix {
    inherit (constructors) splitContribution;
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
  readView = {
    types = serviceTypes;
    inherit (interfaceCatalog) aggregation guaranteeAliases guaranteeDeclarations mergeContract milestones;
    inherit interfaces declarations moduleDeclarations guarantees;
    inherit (constructors) credentialReferenceConfigured featureContribution featureInterfaces forConfiguration forCredentialReferences forProducer forProducers forService instanceOf normalizeCredentialReference splitContribution structuredSource validate valueFromStructuredSource;
    inherit projectContributions projectService;
  };
in {
  name = "serviceManagement";
  inherit readView;
  module.config.aos.abilities = {
    interfaces = moduleDeclarations;
    inherit guarantees;
  };
}
