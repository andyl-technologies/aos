##! Selects native operation scenarios from the checked matrix.
{
  lib,
  matrix,
}:
import ./_native-operation-cells.nix {
  inherit lib matrix;
  separateSystemd = true;
  scenarios = [
    "cancel-pending-invocation"
    "expire-invocation-deadline"
  ];
}
