##! Reference provider that authenticates and aggregates HTTP backend endpoints.
let
  validateEndpoint = endpoint:
    if endpoint.address != "127.0.0.1"
    then throw "HTTP backend must use the IPv4 loopback address"
    else if endpoint.port < 1024 || endpoint.port > 65535
    then throw "HTTP backend port is outside the unprivileged TCP range"
    else if endpoint.transport != "tcp"
    then throw "HTTP backend must use TCP"
    else endpoint;

  compose = context: {
    schema = "aos.ability.composition-fragment/v1";
    requests = [];
    contributions = [];
    resources = [];
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "backend";
        };
        interface = context.interface;
        port = "endpoints";
        value = {
          source = "object";
          fields = builtins.listToAttrs (builtins.map
            (contribution: {
              name = contribution.slot;
              value = {
                source = "literal";
                value = validateEndpoint contribution.value;
              };
            })
            context.contributions);
        };
      }
    ];
    controllers = [];
  };

  transition = _context: {
    schema = "aos.ability.transition-fragment/v1";
    operations = [];
    decisions = [];
    merges = [];
    edges = [];
    exports = [];
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness = [];
    obligations = [];
  };
in {
  inherit compose transition;
}
