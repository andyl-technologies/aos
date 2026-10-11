##! K3s configuration declarations shared by the runtime and integrations.
{lib, ...}: let
  inherit (lib) mkOption types;
  integration = {
    options = {
      disable_flannel = mkOption {
        type = types.bool;
        default = false;
        description = "Disable K3s Flannel for an external network implementation.";
      };
      disable_network_policy = mkOption {
        type = types.bool;
        default = false;
        description = "Disable the built-in network policy controller.";
      };
      disable_kube_proxy = mkOption {
        type = types.bool;
        default = false;
        description = "Disable kube-proxy for a replacement service data plane.";
      };
      node_labels = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = "Additional node labels supplied by this integration.";
      };
    };
  };
in {
  config.aos.abilities.k3sConfiguration.operations.ensure = {
    input.options = {
      path = mkOption {
        type = types.str;
        default = "/run/aos/k3s/config.json";
        description = "Controller-owned JSON configuration path.";
      };
      base = mkOption {
        type = types.submodule {
          options = {
            flannel_backend = mkOption {
              type = types.enum ["vxlan" "host-gw" "wireguard-native" "none"];
              default = "vxlan";
              description = "K3s Flannel backend before integrations override it.";
            };
            disable_network_policy = integration.options.disable_network_policy;
            disable_kube_proxy = integration.options.disable_kube_proxy;
            node_labels = integration.options.node_labels;
          };
        };
        default = {};
        description = "Base settings from the selected K3s role.";
      };
      integrations = mkOption {
        type = types.attrsOf (types.submodule integration);
        default = {};
        description = "Merged add-on settings.";
      };
    };
    result.options.path = mkOption {
      type = types.str;
      description = "Materialized configuration passed to the role launcher.";
    };
  };

  options.aos.k3s.integrations = mkOption {
    extensible = true;
    type = types.attrsOf (types.submodule integration);
    default = {};
    description = "Package-owned K3s configuration definitions.";
  };
}
