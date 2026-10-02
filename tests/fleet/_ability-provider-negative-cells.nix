##! Selects native operation scenarios from the checked matrix.
{
  lib,
  matrix,
}:
import ./_native-operation-cells.nix {
  inherit lib matrix;
  scenarios = [
    "block-dependent-effect"
    "reject-foreign-resource-mutation"
    "reject-uncertain-recovery"
    "fail-manager-after-dispatch-attempt"
  ];
}
