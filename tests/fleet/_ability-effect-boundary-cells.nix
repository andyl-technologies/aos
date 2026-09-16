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
    systemdManager = byAdapters ["systemd-manager"];
    kubernetes = byAdapters ["kubernetes-object" "systemd-bootstrap"];
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.systemdManager
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all
  == builtins.sort builtins.lessThan (map (cell: cell.id) selected);
  assert builtins.all (cell: builtins.elem "dependent-effects-not-executed" cell.postconditions) selected; {
    inherit all alreadyQualified groups scenarios;
  }
