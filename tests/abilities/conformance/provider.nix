##! tests/abilities/conformance/provider.nix - Restricted corpus entry point.
let
  lib = import ./lib {
    system = "@aosBuildSystem@";
  };
  runner = import ./runner.nix {
    inherit (lib) abilities;
    fixtureRoot = ./.;
  };
in {
  compose = arguments: runner.evaluate arguments.case;
  transition = arguments: runner.evaluate arguments.case;
}
