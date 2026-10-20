##! Selects native operation scenarios from the checked matrix.
{
  lib,
  matrix,
}:
import ./_native-operation-cells.nix {
  inherit lib matrix;
  scenarios = [
    "interrupt-after-durable-intent"
    "lose-external-result"
    "interrupt-after-durable-outcome"
  ];
}
