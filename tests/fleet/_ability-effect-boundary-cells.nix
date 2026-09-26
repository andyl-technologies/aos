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
    kubernetes = byAdapters ["kubernetes-object" "systemd-bootstrap"];
    rollout = byAdapters ["image-rollout"];
  };
  all =
    groups.reference
    ++ groups.kubernetes
    ++ groups.rollout;
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all
  == builtins.sort builtins.lessThan (map (cell: cell.id) selected);
  assert builtins.all (cell: builtins.elem "dependent-effects-not-executed" cell.postconditions) selected; {
    inherit all groups scenarios;
  }
