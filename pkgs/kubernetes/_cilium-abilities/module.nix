##! Typed Cilium contribution to the versioned Kubernetes add-on interface.
{
  config,
  lib,
  packageVersion,
  ...
}: let
  inherit (lib) mkIf mkOption;
  abilityTypes = lib.abilities.types;
  cfg = config.cilium;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  objectContract = lib.abilities.interfaces.kubernetesObjectManagement;
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
  objects = {
    requirementTemplates.kubernetes-objects =
      lib.abilities.interfaceSelector {
        inherit (objectContract.contribution.identity) name abi;
      }
      // {
        description = "Contribute the exact Cilium object set to a selected Kubernetes controller.";
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    requests.objects = {
      requirement = "kubernetes-objects";
      consumer = "integration";
      scope = ["objects"];
      parameters = {
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
        prerequisites = [];
      };
    };
  };
  integration = {
    requirementTemplates.k3s-integration =
      lib.abilities.interfaceSelector {
        name = "aos.k3s.integration";
        abi = 1;
      }
      // {
        description = "Contribute Cilium networking settings to a selected K3s controller.";
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    requests.configuration = {
      requirement = "k3s-integration";
      consumer = "integration";
      scope = ["configuration"];
      parameters = {
        disable_flannel = true;
        disable_network_policy = true;
        disable_kube_proxy = cfg.kubeProxyReplacement;
        node_labels = {};
        prerequisites = [];
      };
    };
  };
  contributions = map serviceManagement.splitContribution [objects integration];
in {
  options.cilium = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Contribute the Cilium add-on to the selected Kubernetes owner.";
    };
    kubeProxyReplacement = mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Replace kube-proxy with Cilium's eBPF service implementation.";
    };
    operatorReplicas = mkOption {
      type = abilityTypes.integer {
        minimum = 1;
        maximum = 32;
      };
      default = 1;
      description = "Number of Cilium operator replicas.";
    };
  };

  config.aos.abilities = lib.mkMerge (
    (map (contribution: contribution.declarations) contributions)
    ++ [
      (mkIf cfg.enable (
        lib.mkMerge (
          [{instances.integration = {};}]
          ++ map (contribution: contribution.configured) contributions
        )
      ))
    ]
  );
}
