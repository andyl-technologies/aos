##! Selects native operation scenarios from the checked matrix.
{
  lib,
  matrix,
}:
import ./_native-operation-cells.nix {
  inherit lib matrix;
  scenarios = [
    "activate-retained-target"
    "retain-persistent-orphan"
    "retire-explicit-persistent-target"
  ];
}
