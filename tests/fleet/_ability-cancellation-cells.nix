##! Selects supported-cancellation cells for the reference provider stack.
{
  lib,
  matrix,
}: let
  all = map (cell: cell.id) (
    builtins.filter
    (cell:
      builtins.elemAt (lib.splitString "/" cell.id) 4 == "cancel-unsettled-attempt"
      && cell.recovery.cancel != null)
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
    postgresql = byAdapters ["postgresql"];
    kubernetes = byAdapters ["kubernetes-object"];
    systemd = byAdapters [
      "systemd-bootstrap"
      "systemd-manager"
      "systemd-service-legacy"
    ];
    rollout = byAdapters ["image-rollout"];
  };
in
  assert builtins.length all == 44;
  assert builtins.length groups.reference == 18;
  assert builtins.length groups.foreground == 3;
  assert builtins.length groups.postgresql == 5;
  assert builtins.length groups.kubernetes == 3;
  assert builtins.length groups.systemd == 6;
  assert builtins.length groups.rollout == 9;
  assert builtins.length (lib.unique all) == 44; {
    inherit all groups;
  }
