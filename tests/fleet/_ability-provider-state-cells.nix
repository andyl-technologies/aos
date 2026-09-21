##! Selects native provider-state cells from the realized adapter matrix.
{
  lib,
  matrix,
}: let
  scenarios = [
    "adopt-compatible-state"
    "activate-retained-target"
    "reject-unsupported-transfer"
  ];
  inapplicableById = builtins.listToAttrs (
    map (entry: {
      name = entry.cell_id;
      value = entry.reason;
    })
    matrix.applicability.inapplicable_cells
  );
  compatibleCellId = cell: "${cell.adapter}/${cell.interface.name}/abi-${toString cell.interface.abi}/${cell.method}/adopt-compatible-state";
  hasUnsupportedTransfer = cell: builtins.hasAttr (compatibleCellId cell) inapplicableById;
  scenarioOf = cell: builtins.elemAt (lib.splitString "/" cell.id) 4;
  selected = builtins.filter (cell: let
    scenario = scenarioOf cell;
  in
    builtins.elem scenario scenarios
    && (
      if scenario == "adopt-compatible-state"
      then cell.adapter == "image-rollout"
      else hasUnsupportedTransfer cell || cell.adapter == "image-rollout"
    ))
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
  all = groups.reference ++ groups.kubernetes ++ groups.rollout;
  compatible = builtins.filter (lib.hasSuffix "/adopt-compatible-state") all;
  retained = builtins.filter (lib.hasSuffix "/activate-retained-target") all;
  unsupported = builtins.filter (lib.hasSuffix "/reject-unsupported-transfer") all;
  blockedCompatible =
    builtins.filter (
      cell: builtins.hasAttr cell.id inapplicableById
    )
    matrix.cells;
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all
  == builtins.sort builtins.lessThan (map (cell: cell.id) selected);
  assert builtins.sort builtins.lessThan (compatible ++ retained ++ unsupported)
  == builtins.sort builtins.lessThan all;
  assert map (cell: cell.id) blockedCompatible == map (entry: entry.cell_id) matrix.applicability.inapplicable_cells;
  assert builtins.all (cell:
    !lib.hasSuffix "/reject-unsupported-transfer" cell.id
    || builtins.elem "dependent-effects-not-executed" cell.postconditions)
  selected; {
    inherit
      all
      blockedCompatible
      compatible
      groups
      retained
      scenarios
      unsupported
      ;
  }
