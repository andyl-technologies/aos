##! Typed runtime configuration for the standalone kubelet package.
{
  config,
  lib,
  ...
}: let
  cfg = config.kubelet;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  kubeconfigRef =
    if cfg.kubeconfig.ref == null
    then {}
    else {kubeconfig.ref = cfg.kubeconfig.ref;};
in {
  options.kubelet = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned standalone kubelet service.";
    };
    nodeName = mkOption {
      type = types.strMatching "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
      default = "aos-node";
      description = "Node name reported to the Kubernetes API.";
    };
    address = mkOption {
      type = types.strMatching "[A-Za-z0-9][A-Za-z0-9.:-]*";
      default = "0.0.0.0";
      description = "Address for the authenticated kubelet HTTPS endpoint.";
    };
    runtimeEndpoint = mkOption {
      type = types.strMatching "unix:///[^[:space:]]+";
      default = "unix:///run/containerd/containerd.sock";
      description = "CRI runtime endpoint used to create pods and images.";
    };
    cgroupDriver = mkOption {
      type = types.enum ["cgroupfs" "systemd"];
      default = "systemd";
      description = "Cgroup manager shared with the container runtime.";
    };
    clusterDns = mkOption {
      type = types.listOf (types.strMatching "[0-9a-fA-F:.]+");
      default = ["10.43.0.10"];
      description = "DNS service addresses written into pod resolv.conf files.";
    };
    clusterDomain = mkOption {
      type = types.strMatching "[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?";
      default = "cluster.local";
      description = "DNS domain appended to Kubernetes service names.";
    };
    staticPodPath = mkOption {
      type = types.strMatching "/[^[:space:]]+";
      default = "/var/lib/kubelet/manifests";
      description = "Host directory watched for static pod manifests.";
    };
    maxPods = mkOption {
      type = positiveInt;
      default = 110;
      description = "Maximum number of pods admitted on this node.";
    };
    failSwapOn = mkOption {
      type = types.bool;
      default = true;
      description = "Refuse to start when swap is enabled on the host.";
    };
    registerNode = mkOption {
      type = types.bool;
      default = true;
      description = "Register and maintain this node through the Kubernetes API.";
    };
    authentication.anonymous = mkOption {
      type = types.bool;
      default = false;
      description = "Permit unauthenticated requests to the kubelet HTTPS endpoint.";
    };
    kubeconfig = mkOption {
      type = types.submodule ({...}: {
        config._module.strict = true;
        options.ref = mkOption {
          type = types.nullOr (types.strMatching "(desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
          default = null;
          description = "Opaque reference to the kubeconfig used for API authentication.";
        };
      });
      default = {};
      description = "Kubernetes API client identity delivered as a systemd credential.";
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || !cfg.registerNode || cfg.kubeconfig.ref != null;
        message = "kubelet.enable with kubelet.registerNode requires kubelet.kubeconfig.ref";
      }
      {
        assertion = cfg.clusterDns != [];
        message = "kubelet.clusterDns must contain at least one address";
      }
    ];
    kubelet.config = {
      runtime = {
        KUBELET_ENABLED = cfg.enable;
        KUBELET_NODE_NAME = cfg.nodeName;
      };
      config = {
        apiVersion = "kubelet.config.k8s.io/v1beta1";
        kind = "KubeletConfiguration";
        inherit (cfg) address cgroupDriver clusterDomain failSwapOn maxPods registerNode staticPodPath;
        clusterDNS = cfg.clusterDns;
        containerRuntimeEndpoint = cfg.runtimeEndpoint;
        port = 10250;
        readOnlyPort = 0;
        authentication = {
          anonymous.enabled = cfg.authentication.anonymous;
          webhook.enabled = true;
        };
        authorization.mode = "Webhook";
      };
    };
    kubelet.credentials = kubeconfigRef;
  };
}
