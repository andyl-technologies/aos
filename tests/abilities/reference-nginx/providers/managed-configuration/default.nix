##! Pure managed-configuration provider for the checked source fixture.
let
  compose = context: let
    managedConfiguration = context.interface;
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    resourceFor = contribution: {
      provider = context.provider;
      key = "${contribution.slot}-configuration";
    };
    render = contribution:
      builtins.concatStringsSep "\n" (
        builtins.map
        (virtualHost: ''
          server {
            listen 80;
            ${
            if virtualHost.tls or false
            then "listen 443 ssl;"
            else ""
          }
            server_name ${virtualHost.host};
          }
        '')
        contribution.value.virtualHosts
      );
    fieldMap = makeValue:
      builtins.listToAttrs (
        builtins.map
        (contribution: {
          name = contribution.slot;
          value = makeValue contribution;
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
          group = "configuration";
        };
        interface = managedConfiguration;
        port = "published-configurations";
        value = {
          source = "object";
          fields = fieldMap (contribution: {
            source = "resource-reference";
            reference = {
              interface = managedConfiguration;
              resource = resourceFor contribution;
              operations = ["publish" "read"];
              lifetime = "instance";
            };
          });
        };
      }
      {
        aggregate = {
          provider = context.provider;
          group = "configuration";
        };
        interface = managedConfiguration;
        port = "rendered-configurations";
        value = {
          source = "object";
          fields = fieldMap (contribution: {
            source = "literal";
            value = render contribution;
          });
        };
      }
    ];
    controllers =
      builtins.map
      (contribution: {
        resource = resourceFor contribution;
        controller = {
          provider = context.provider;
          group = "configuration";
        };
      })
      contributions;
  };
in {
  inherit compose;
  transition = _context: {};
}
