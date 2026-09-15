##! tests/abilities/conformance/provider.nix - Restricted corpus entry point.
let
  lib = import ./lib {
    system = "@aosBuildSystem@";
  };
  evaluate = arguments:
    lib.abilities.schemas.checkValue arguments.case.schema arguments.case.value;
in {
  compose = evaluate;
  transition = evaluate;
}
