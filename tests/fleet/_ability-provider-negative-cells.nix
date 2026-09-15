##! Defines the closed provider-negative native-adapter qualification cohort.
{
  lib,
  matrix,
}: let
  scenarios = [
    "block-dependent-effect"
    "reject-foreign-resource-mutation"
  ];
  alreadyQualified = [
    "managed-configuration/aos.managed-configuration-effects/abi-1/publish/reject-foreign-resource-mutation"
    "service-management/aos.service-management/abi-1/reload/block-dependent-effect"
  ];
  selected = builtins.filter (cell:
    builtins.elem (builtins.elemAt (lib.splitString "/" cell.id) 4) scenarios
    && !builtins.elem cell.id alreadyQualified)
  matrix.cells;
  byAdapters = adapters:
    map (cell: cell.id) (builtins.filter (cell: builtins.elem cell.adapter adapters) selected);
  groups = {
    reference = byAdapters [
      "credential-delivery"
      "host-network-policy"
      "host-storage"
      "managed-configuration"
      "network-endpoint"
      "nginx-validation"
      "service-management"
    ];
    foreground-process = byAdapters ["foreground-process"];
    systemd-manager = byAdapters ["systemd-manager"];
    kubernetes-object = byAdapters ["kubernetes-object"];
    systemd-bootstrap = byAdapters ["systemd-bootstrap"];
    kubernetes = groups.kubernetes-object ++ groups.systemd-bootstrap;
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.foreground-process
    ++ groups.systemd-manager
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all
  == builtins.sort builtins.lessThan (map (cell: cell.id) selected); {
    inherit all groups scenarios;
  }
