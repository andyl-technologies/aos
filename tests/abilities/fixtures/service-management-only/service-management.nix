##! Selects only the service-management domain for composition checks.
{
  types,
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}:
import ../../../../modules/abilities/_interfaces/service-management.nix {
  inherit
    types
    declareInterface
    descriptorFor
    interfaceDocumentFromDeclaration
    interfaceIdentity
    ;
}
