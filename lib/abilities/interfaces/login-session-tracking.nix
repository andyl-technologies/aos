##! Canonical provider-neutral login-session tracking selection.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "login-session-tracking";
  requestType = types.record {
    fields.enabled = types.boolean;
  };
  declaration = declareInterface {
    name = "aos.identity.login-session-tracking";
    abi = 1;
    description = "Selects integration that registers authenticated login sessions with the system manager.";
    inherit requestType;
    outputs.selected-policy = {
      schema = requestType;
      phase = "planning";
      lifetime = "instance";
      visibility = "protected";
      description = "Returns the selected login-session tracking policy for this system instance.";
    };
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
  name = "loginSessionTracking";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
