##! Cilium configuration and provider-neutral Kubernetes requirement.
{
  config,
  lib,
  packageVersion,
  ...
}: let
  inherit (lib) mkIf mkOption;
  inherit (lib.abilities) types;
  cfg = config.cilium;
in {
  options.cilium = {
    enable = mkOption {
      type = types.boolean;
      default = false;
      description = "Contribute the Cilium add-on to the selected Kubernetes owner.";
    };
    kubeProxyReplacement = mkOption {
      type = types.boolean;
      default = true;
      description = "Replace kube-proxy with Cilium's eBPF service implementation.";
    };
    operatorReplicas = mkOption {
      type = types.integer {
        minimum = 1;
        maximum = 32;
      };
      default = 1;
      description = "Number of Cilium operator replicas.";
    };
  };

  config = {
    aos.abilities.requirementTemplates.k3s =
      lib.abilities.interfaceSelector {
        name = "aos.k3s-cluster";
        abi = 1;
      }
      // {
        description = "Contribute Cilium resources to the selected Kubernetes cluster.";
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };

    k3s.integrations.cni.cilium = mkIf cfg.enable {
      disableFlannel = true;
      disableNetworkPolicy = true;
      disableKubeProxy = cfg.kubeProxyReplacement;
    };
    k3s.integrations.resources.cilium = mkIf cfg.enable {
      apiVersion = "helm.cattle.io/v1";
      kind = "HelmChart";
      name = "cilium";
      namespace = "kube-system";
      priority = 100;
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
  };
}
