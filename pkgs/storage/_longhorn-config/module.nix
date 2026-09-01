##! Typed Longhorn contribution to the versioned Kubernetes add-on interface.
{
  config,
  lib,
  outputs,
  ...
}: let
  inherit (lib) mkIf mkOption types;
  package = builtins.fromJSON (builtins.readFile "${outputs.self}/share/longhorn-package.json");
  cfg = config.longhorn;
  values = ''
    defaultSettings:
      defaultReplicaCount: "${toString cfg.defaultReplicaCount}"
    persistence:
      defaultClassReplicaCount: ${toString cfg.defaultReplicaCount}
  '';
in {
  options.longhorn = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Contribute the Longhorn storage add-on to the selected Kubernetes owner.";
    };
    defaultReplicaCount = mkOption {
      type = types.addCheck types.int (value: value >= 1 && value <= 20);
      default = 3;
      description = "Default number of replicas for Longhorn volumes.";
    };
    nodeLabel = mkOption {
      type = types.strMatching "[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?";
      default = "true";
      description = "Value of the package-owned Longhorn scheduling node label.";
    };
  };

  config.k3s.integrations.csi.longhorn = mkIf cfg.enable {
    nodeLabels."node.longhorn.io/create-default-disk" = cfg.nodeLabel;
  };
  config.k3s.integrations.resources.longhorn = mkIf cfg.enable {
    priority = 200;
    content = ''
      apiVersion: helm.cattle.io/v1
      kind: HelmChart
      metadata:
        name: longhorn
        namespace: kube-system
      spec:
        chart: longhorn
        repo: https://charts.longhorn.io
        targetNamespace: longhorn-system
        version: ${package.version}
        valuesContent: |-
      ${lib.concatMapStringsSep "\n" (line: "      ${line}") (lib.splitString "\n" values)}
    '';
  };
}
