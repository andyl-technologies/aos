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
  specializedAdapters = [
    "image-rollout"
    "kubernetes-object"
    "service-management"
    "systemd-bootstrap"
    "systemd-manager"
    ];
  groups = {
    reference =
      builtins.filter (
        cell: !builtins.elem (builtins.head (lib.splitString "/" cell)) specializedAdapters
      )
      all;
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
    ++ groups.kubernetes
    ++ groups.systemd
    ++ groups.rollout
  )
  == builtins.sort builtins.lessThan all; {
    inherit all groups;
  }
