##! Longhorn configuration and provider-neutral Kubernetes requirements.
{
  config,
  lib,
  packageVersion,
  ...
}: let
  inherit (lib) mkIf mkOption;
  abilityTypes = lib.abilities.types;
  cfg = config.longhorn;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  objectInterface = lib.abilities.interfaceSelector {
    name = "aos.kubernetes.objects";
    abi = 1;
  };
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
  objects = {
    requirementTemplates.kubernetes-objects =
      objectInterface
      // {
        description = "Contribute the exact Longhorn object set to a selected Kubernetes controller.";
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
            key = "longhorn";
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
        description = "Contribute the Longhorn node label to a selected K3s controller.";
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
        disable_flannel = false;
        disable_network_policy = false;
        disable_kube_proxy = false;
        node_labels."node.longhorn.io/create-default-disk" = cfg.nodeLabel;
        prerequisites = [];
      };
    };
  };
  contributions = map serviceManagement.splitContribution [objects integration];
in {
  options.longhorn = {
    enable = mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Contribute the Longhorn storage add-on to the selected Kubernetes owner.";
    };
    defaultReplicaCount = mkOption {
      type = abilityTypes.integer {
        minimum = 1;
        maximum = 20;
      };
      default = 3;
      description = "Default number of replicas for Longhorn volumes.";
    };
    nodeLabel = mkOption {
      type = abilityTypes.refined {
        name = "Kubernetes label value";
        description = "a bounded Kubernetes label value";
        type = abilityTypes.string {
          maxLength = 253;
          syntax = null;
        };
        constraints = [{kind = "string-pattern"; pattern = "([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?";}];
      };
      default = "true";
      description = "Value of the package-owned Longhorn scheduling node label.";
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
