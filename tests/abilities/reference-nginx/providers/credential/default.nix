##! Pure credential-delivery provider for the checked source fixture.
let
  compose = context: let
    credentialDelivery = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-credential-view";
    };
    fields = builtins.listToAttrs (
      builtins.map
      (contribution: {
        name = contribution.slot;
        value = {
          source = "resource-reference";
          reference = {
            interface = credentialDelivery;
            resource = resourceFor contribution;
            operations = ["deliver"];
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
          group = "credentials";
        };
        interface = credentialDelivery;
        port = "credential-views";
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
          group = "credentials";
        };
      })
      contributions;
  };
in {
  inherit compose;
  transition = _context: {};
}
