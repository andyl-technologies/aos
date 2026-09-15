##! Selects cells whose concrete production operation determines cancellation.
{
  lib,
  matrix,
}: let
  all = map (cell: cell.id) (
    builtins.filter
    (cell:
      builtins.elemAt (lib.splitString "/" cell.id) 4
      == "cancel-unsettled-attempt")
    matrix.cells
  );
  byAdapters = adapters:
    builtins.filter
    (cell: builtins.elem (builtins.head (lib.splitString "/" cell)) adapters)
    all;
  groups = {
    reference = byAdapters [
      "credential-delivery"
      "host-network-policy"
      "host-storage"
      "managed-configuration"
      "network-endpoint"
      "nginx-validation"
    ];
    foreground = byAdapters ["foreground-process"];
    kubernetes = byAdapters ["kubernetes-object"];
    systemd = byAdapters [
      "systemd-bootstrap"
      "systemd-manager"
      "service-management"
    ];
    rollout = byAdapters ["image-rollout"];
  };
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan (
    groups.reference
    ++ groups.foreground
    ++ groups.kubernetes
    ++ groups.systemd
    ++ groups.rollout
  )
  == builtins.sort builtins.lessThan all; {
    inherit all groups;
  }
