##! Canonical provider-neutral crash-dump collection policy.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "crash-dump-policy";
  requestType = types.record {
    fields.enabled = types.boolean;
  };
  declaration = declareInterface {
    name = "aos.system.crash-dump-policy";
    abi = 1;
    description = "Selects whether the system collects process crash dumps.";
    inherit requestType;
    outputs = {};
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = alias;
    };
  };
  document = interfaceDocumentFromDeclaration declaration;
  identity = interfaceIdentity document;
  readView = {
    interface = {
      inherit alias declaration document identity requestType;
      methods = [];
    };
    declarations.${alias} = declaration;
  };
in {
  name = "crashDumpPolicy";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
