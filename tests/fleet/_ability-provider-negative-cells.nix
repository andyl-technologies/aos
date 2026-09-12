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
    "systemd-service-legacy/aos.systemd-service-effects/abi-1/reload/block-dependent-effect"
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
      "systemd-service-legacy"
    ];
    postgresql = byAdapters ["postgresql"];
    systemd-manager = byAdapters ["systemd-manager"];
    kubernetes-object = byAdapters ["kubernetes-object"];
    systemd-bootstrap = byAdapters ["systemd-bootstrap"];
    kubernetes = groups.kubernetes-object ++ groups.systemd-bootstrap;
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.postgresql
    ++ groups.systemd-manager
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length matrix.cells == 1316;
  assert builtins.length all == 92;
  assert builtins.length (lib.unique all) == 92;
  assert builtins.length groups.reference == 42;
  assert builtins.length groups.postgresql == 10;
  assert builtins.length groups.systemd-manager == 10;
  assert builtins.length groups.kubernetes == 12;
  assert builtins.length groups.rollout == 18; {
    inherit all groups scenarios;
  }
