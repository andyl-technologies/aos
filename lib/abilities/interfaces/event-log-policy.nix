##! Canonical provider-neutral event-log retention and delivery policy.
{
  types,
  declareInterface,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  alias = "event-log-policy";
  requestType = types.record {
    fields = {
      storage = types.enum ["persistent" "volatile" "automatic"];
      max_retention_seconds = types.integer {
        minimum = 1;
        maximum = 315576000;
      };
      max_use_bytes = types.integer {
        minimum = 1048576;
        maximum = 1125899906842624;
      };
      max_file_bytes = types.integer {
        minimum = 1048576;
        maximum = 1125899906842624;
      };
      rate_limit_interval_millis = types.integer {
        minimum = 1;
        maximum = 86400000;
      };
      rate_limit_burst = types.integer {
        minimum = 1;
        maximum = 4294967295;
      };
      forward_to_syslog = types.boolean;
      compress = types.boolean;
    };
  };
  declaration = declareInterface {
    name = "aos.system.event-log-policy";
    abi = 1;
    description = "Selects bounded event-log storage, retention, rate limiting, and forwarding policy.";
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
  name = "eventLogPolicy";
  inherit readView;
  module.config.aos.abilities.interfaces = readView.declarations;
}
