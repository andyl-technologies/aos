##! Typed Cilium contribution to the versioned Kubernetes add-on interface.
{
  config,
  lib,
  outputs,
  ...
}: let
  inherit (lib) mkIf mkOption types;
  package = builtins.fromJSON (builtins.readFile "${outputs.self}/share/cilium-package.json");
  cfg = config.cilium;
  values = ''
    kubeProxyReplacement: ${
      if cfg.kubeProxyReplacement
      then "true"
      else "false"
    }
    operator:
      replicas: ${toString cfg.operatorReplicas}
  '';
in {
  options.cilium = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Contribute the Cilium add-on to the selected Kubernetes owner.";
    };
    kubeProxyReplacement = mkOption {
      type = types.bool;
      default = true;
      description = "Replace kube-proxy with Cilium's eBPF service implementation.";
    };
    operatorReplicas = mkOption {
      type = types.addCheck types.int (value: value >= 1 && value <= 32);
      default = 1;
      description = "Number of Cilium operator replicas.";
    };
  };

  config = mkIf cfg.enable {
    k3s.integrations = {
      cni.cilium = {
        disableFlannel = true;
        disableNetworkPolicy = true;
        disableKubeProxy = cfg.kubeProxyReplacement;
      };
      resources.cilium = {
        priority = 100;
        content = ''
          apiVersion: helm.cattle.io/v1
          kind: HelmChart
          metadata:
            name: cilium
            namespace: kube-system
          spec:
            chart: cilium
            repo: https://helm.cilium.io/
            targetNamespace: kube-system
            version: ${package.version}
            valuesContent: |-
          ${lib.concatMapStringsSep "\n" (line: "      ${line}") (lib.splitString "\n" values)}
        '';
      };
    };
  };
}
