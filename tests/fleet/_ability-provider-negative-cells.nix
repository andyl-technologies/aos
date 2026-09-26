##! Defines the closed provider-negative native-adapter qualification cohort.
{
  lib,
  matrix,
}: let
  scenarios = [
    "block-dependent-effect"
    "reject-foreign-resource-mutation"
  ];
  selected = builtins.filter (cell:
    builtins.elem (builtins.elemAt (lib.splitString "/" cell.id) 4) scenarios)
  matrix.cells;
  byAdapters = adapters:
    map (cell: cell.id) (builtins.filter (cell: builtins.elem cell.adapter adapters) selected);
  specializedAdapters = [
    "image-rollout"
    "kubernetes-object"
    "systemd-bootstrap"
  ];
  groups = {
    reference = map (cell: cell.id) (
      builtins.filter (cell: !builtins.elem cell.adapter specializedAdapters) selected
    );
    kubernetes-object = byAdapters ["kubernetes-object"];
    systemd-bootstrap = byAdapters ["systemd-bootstrap"];
    kubernetes = groups.kubernetes-object ++ groups.systemd-bootstrap;
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all
  == builtins.sort builtins.lessThan (map (cell: cell.id) selected); {
    inherit all groups scenarios;
  }
