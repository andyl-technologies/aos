##! Defines the closed provider-effect interruption cohort for RFC-0022.
{
  lib,
  matrix,
}: let
  scenarios = [
    "interrupt-after-acquisition"
    "interrupt-after-durable-intent"
    "lose-external-result"
    "interrupt-after-durable-outcome"
  ];
  alreadyQualified = [
    "managed-configuration/aos.managed-configuration-effects/abi-1/publish/interrupt-after-durable-intent"
    "managed-configuration/aos.managed-configuration-effects/abi-1/publish/lose-external-result"
    "managed-configuration/aos.managed-configuration-effects/abi-1/publish/interrupt-after-durable-outcome"
    "postgresql/aos.postgresql-effects/abi-1/restart/lose-external-result"
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
    systemdManager = byAdapters ["systemd-manager"];
    kubernetes = byAdapters ["kubernetes-object" "systemd-bootstrap"];
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.systemdManager
    ++ groups.postgresql
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length matrix.cells == 1316;
  assert builtins.length all == 184;
  assert builtins.length (lib.unique all) == 184;
  assert builtins.length groups.reference == 85;
  assert builtins.length groups.postgresql == 19;
  assert builtins.length groups.systemdManager == 20;
  assert builtins.length groups.kubernetes == 24;
  assert builtins.length groups.rollout == 36;
  assert builtins.all (cell: builtins.length cell.postconditions == 4) selected;
  {
    inherit all alreadyQualified groups scenarios;
  }
