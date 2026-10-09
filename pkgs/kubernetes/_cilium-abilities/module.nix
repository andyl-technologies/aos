##! Typed Cilium definition to the versioned Kubernetes add-on interface.
{
  config,
  lib,
  packageVersion,
  ...
}: let
  inherit (lib) mkOption;
  cfg = config.aos.cilium;
  chartObject = {
    apiVersion = "helm.cattle.io/v1";
    kind = "HelmChart";
    metadata = {
      name = "cilium";
      namespace = "kube-system";
    };
    spec = {
      chart = "cilium";
      repo = "https://helm.cilium.io/";
      targetNamespace = "kube-system";
      version = packageVersion;
      valuesContent = builtins.toJSON {
        kubeProxyReplacement = cfg.kubeProxyReplacement;
        operator.replicas = cfg.operatorReplicas;
      };
    };
  };
in {
  options.aos.cilium = {
    enable = mkOption {
      type = lib.types.bool;
      default = false;
      description = "Contribute the Cilium add-on to the selected Kubernetes owner.";
    };
    kubeProxyReplacement = mkOption {
      type = lib.types.bool;
      default = true;
      description = "Replace kube-proxy with Cilium's eBPF service implementation.";
    };
    operatorReplicas = mkOption {
      type = lib.types.ints.between 1 32;
      default = 1;
      description = "Number of Cilium operator replicas.";
    };
  };

  config = lib.mkIf cfg.enable {
    aos.kubernetes.objectSets.cilium = {
      enable = true;
      objects = [
        {
          key = "cilium";
          api_version = chartObject.apiVersion;
          kind = chartObject.kind;
          namespace = chartObject.metadata.namespace;
          name = chartObject.metadata.name;
          content = builtins.toJSON chartObject;
        }
      ];
    };
    aos.k3s.integrations.cilium = {
      disable_flannel = true;
      disable_network_policy = true;
      disable_kube_proxy = cfg.kubeProxyReplacement;
    };
  };
}
