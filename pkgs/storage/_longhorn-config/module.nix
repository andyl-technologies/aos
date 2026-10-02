##! Longhorn configuration and provider-neutral Kubernetes requirements.
{
  config,
  lib,
  packageVersion,
  ...
}: let
  inherit (lib) mkOption;

  cfg = config.aos.longhorn;
  chartObject = {
    apiVersion = "helm.cattle.io/v1";
    kind = "HelmChart";
    metadata = {
      name = "longhorn";
      namespace = "kube-system";
    };
    spec = {
      chart = "longhorn";
      repo = "https://charts.longhorn.io";
      targetNamespace = "longhorn-system";
      version = packageVersion;
      valuesContent = builtins.toJSON {
        defaultSettings.defaultReplicaCount = builtins.toString cfg.defaultReplicaCount;
        persistence.defaultClassReplicaCount = cfg.defaultReplicaCount;
      };
    };
  };
in {
  options.aos.longhorn = {
    enable = mkOption {
      type = lib.types.bool;
      default = false;
      description = "Contribute the Longhorn storage add-on to the selected Kubernetes owner.";
    };
    defaultReplicaCount = mkOption {
      type = lib.types.ints.between 1 20;
      default = 3;
      description = "Default number of replicas for Longhorn volumes.";
    };
    nodeLabel = mkOption {
      type = lib.types.addCheck lib.types.str (value:
        builtins.stringLength value
        <= 253
        && builtins.match "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?" value != null);
      default = "true";
      description = "Value of the package-owned Longhorn scheduling node label.";
    };
  };

  config = lib.mkIf cfg.enable {
    aos.kubernetes.objectSets.longhorn = {
      enable = true;
      objects = [
        {
          key = "longhorn";
          api_version = chartObject.apiVersion;
          kind = chartObject.kind;
          namespace = chartObject.metadata.namespace;
          name = chartObject.metadata.name;
          content = builtins.toJSON chartObject;
        }
      ];
    };
    aos.k3s.integrations.longhorn.node_labels."node.longhorn.io/create-default-disk" = cfg.nodeLabel;
  };
}
