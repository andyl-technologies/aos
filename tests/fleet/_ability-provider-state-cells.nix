##! Selects native provider-state cells from the realized adapter matrix.
{
  lib,
  matrix,
}: let
  scenarios = [
    "activate-retained-target"
    "reject-unsupported-transfer"
  ];
  selected = builtins.filter (cell:
    cell.adapter
    != "postgresql"
    && builtins.elem (builtins.elemAt (lib.splitString "/" cell.id) 4) scenarios)
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
      "systemd-service-legacy"
    ];
    kubernetes = byAdapters ["kubernetes-object" "systemd-bootstrap"];
    rollout = byAdapters ["image-rollout"];
    foreground = byAdapters ["foreground-process"];
  };
  all = groups.reference ++ groups.kubernetes ++ groups.rollout ++ groups.foreground;
  retained = builtins.filter (lib.hasSuffix "/activate-retained-target") all;
  unsupported = builtins.filter (lib.hasSuffix "/reject-unsupported-transfer") all;
in
  assert builtins.length all == 90;
  assert builtins.length (lib.unique all) == 90;
  assert builtins.length groups.reference == 54;
  assert builtins.length groups.kubernetes == 12;
  assert builtins.length groups.rollout == 18;
  assert builtins.length groups.foreground == 6;
  assert builtins.length retained == 45;
  assert builtins.length unsupported == 45;
  assert builtins.all (cell:
    builtins.length cell.postconditions
    == (
      if lib.hasSuffix "/activate-retained-target" cell.id
      then 6
      else 7
    ))
  selected; {
    inherit all groups retained scenarios unsupported;
  }
