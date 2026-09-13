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
    matrix.inapplicable_cells
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
  groups = {
    reference = byAdapters [
      "credential-delivery"
      "host-network-policy"
      "host-storage"
      "managed-configuration"
      "network-endpoint"
      "nginx-validation"
      "systemd-manager"
      "service-management"
    ];
    kubernetes = byAdapters ["kubernetes-object" "systemd-bootstrap"];
    rollout = byAdapters ["image-rollout"];
    foreground = byAdapters ["foreground-process"];
  };
  all = groups.reference ++ groups.kubernetes ++ groups.rollout ++ groups.foreground;
  compatible = builtins.filter (lib.hasSuffix "/adopt-compatible-state") all;
  retained = builtins.filter (lib.hasSuffix "/activate-retained-target") all;
  unsupported = builtins.filter (lib.hasSuffix "/reject-unsupported-transfer") all;
  blockedCompatible =
    builtins.filter (
      cell: builtins.hasAttr cell.id inapplicableById
    )
    matrix.cells;
  instanceLifetimeBlocked = map (entry: entry.cell_id) (
    builtins.filter (entry: entry.reason == "non-persistent-lifetime") matrix.inapplicable_cells
  );
  missingStateFormatBlocked = map (entry: entry.cell_id) (
    builtins.filter (entry: entry.reason == "missing-authenticated-state-format") matrix.inapplicable_cells
  );
in
  assert builtins.length all == 101;
  assert builtins.length (lib.unique all) == 101;
  assert builtins.length groups.reference == 56;
  assert builtins.length groups.kubernetes == 12;
  assert builtins.length groups.rollout == 27;
  assert builtins.length groups.foreground == 6;
  assert builtins.length retained == 46;
  assert builtins.length unsupported == 46;
  assert builtins.length compatible == 9;
  assert builtins.length blockedCompatible == 37;
  assert builtins.length instanceLifetimeBlocked == 37;
  assert builtins.length missingStateFormatBlocked == 0;
  assert builtins.all (cell:
    builtins.length cell.postconditions
    == (
      if lib.hasSuffix "/reject-unsupported-transfer" cell.id
      then 7
      else 6
    ))
  selected; {
    inherit
      all
      blockedCompatible
      compatible
      groups
      instanceLifetimeBlocked
      missingStateFormatBlocked
      retained
      scenarios
      unsupported
      ;
  }
