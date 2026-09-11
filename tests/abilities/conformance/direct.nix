##! tests/abilities/conformance/direct.nix - One direct Nix corpus evaluation.
{
  caseJson,
  system,
}: let
  lib = import ./lib {inherit system;};
  runner = import ./runner.nix {
    inherit (lib) abilities;
    fixtureRoot = ./.;
  };
  case = builtins.fromJSON caseJson;
  result = runner.evaluate case;
in
  builtins.deepSeq result result
