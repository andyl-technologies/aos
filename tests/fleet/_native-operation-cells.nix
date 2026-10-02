##! Partitions real native matrix cells by their declared operation domain.
{
  lib,
  matrix,
  scenarios,
  separateSystemd ? false,
}: let
  selected = builtins.filter (cell: builtins.elem cell.scenario.id scenarios) matrix.cells;
  ability = cell: cell.operation.ability;
  rolloutAbilities = ["imageRollout" "imageSelection" "imageRetirement"];
  kubernetesAbilities = ["kubernetes" "k3sConfiguration"];
  systemdAbilities = ["serviceManagement" "configurationLower"];
  select = predicate: map (cell: cell.id) (builtins.filter predicate selected);
  groups = {
    rollout = select (cell: builtins.elem (ability cell) rolloutAbilities);
    kubernetes = select (cell: builtins.elem (ability cell) kubernetesAbilities);
    systemd = select (cell: separateSystemd && builtins.elem (ability cell) systemdAbilities);
    reference = select (cell: !builtins.elem (ability cell) (rolloutAbilities ++ kubernetesAbilities ++ lib.optionals separateSystemd systemdAbilities));
  };
  all = lib.concatLists (builtins.attrValues groups);
in
  assert builtins.length all == builtins.length (lib.unique all);
  assert builtins.sort builtins.lessThan all == builtins.sort builtins.lessThan (map (cell: cell.id) selected); {
    inherit all groups scenarios;
  }
