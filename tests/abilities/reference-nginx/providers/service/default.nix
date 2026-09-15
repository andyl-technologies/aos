##! Pure logical service-definition provider for the checked source fixture.
let
  compose = context: let
    serviceDefinition = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-service";
    };
    fields = builtins.listToAttrs (
      builtins.map
      (contribution: {
        name = contribution.slot;
        value = {
          source = "resource-reference";
          reference = {
            interface = serviceDefinition;
            resource = resourceFor contribution;
            operations = ["observe" "reload" "restart" "start" "stop"];
            lifetime = "instance";
          };
        };
      })
      contributions
    );
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [];
    contributions = [];
    resources =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        revision = "sha256:${builtins.hashString "sha256" (builtins.toJSON contribution.value)}";
      })
      contributions;
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "services";
        };
        interface = serviceDefinition;
        port = "managers";
        value = {
          source = "object";
          inherit fields;
        };
      }
    ];
    controllers =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        controller = {
          provider = context.provider;
          group = "services";
        };
      })
      contributions;
  };
in {
  inherit compose;

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
}
