##! Kubernetes object declarations shared by controllers and add-on packages.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption types;
  objectSet = {
    options.objects = mkOption {
      type = types.listOf (types.submodule {
        options = {
          key = mkOption {
            type = types.str;
            description = "Unique object key within the controller.";
          };
          api_version = mkOption {
            type = types.str;
            description = "Exact Kubernetes API group and version.";
          };
          kind = mkOption {
            type = types.str;
            description = "Kubernetes resource kind.";
          };
          namespace = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Resource namespace, or null for a cluster resource.";
          };
          name = mkOption {
            type = types.str;
            description = "Kubernetes resource name.";
          };
          content = mkOption {
            type = types.str;
            description = "Canonical JSON document matching the declared resource identity.";
          };
        };
      });
      default = [];
      description = "Exact objects owned and reconciled by the controller.";
    };
  };
in {
  config.aos.abilities.kubernetes.operations.ensure = {
    input.options = {
      kubeconfig = mkOption {
        type = types.str;
        description = "Absolute path to the selected cluster's kubeconfig.";
      };
      object_sets = mkOption {
        type = types.attrsOf (types.submodule objectSet);
        default = {};
        description = "Merged package object sets.";
      };
    };
    result.options.cluster = mkOption {
      type = types.str;
      description = "Observed kube-system namespace UID identifying the cluster incarnation.";
    };
  };

  options.aos.kubernetes.objectSets = mkOption {
    extensible = true;
    type = types.attrsOf (types.submodule [objectSet {options.enable = lib.mkEnableOption "this Kubernetes object set";}]);
    default = {};
    description = "Package definitions merged before the selected controller derives its effect.";
  };
}
