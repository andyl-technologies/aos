##! tests/abilities/conformance/direct.nix - One direct Nix corpus evaluation.
{
  caseJson,
  system,
}: let
  lib = import ./lib {inherit system;};
  abilityPackageRenderer = import ./ability-package-renderer.nix {
    inherit lib;
    inherit (lib) abilities;
  };
  runner = import ./runner.nix {
    inherit (lib) abilities;
    inherit abilityPackageRenderer;
    fixtureRoot = ./.;
  };
  case = builtins.fromJSON caseJson;
  result = runner.evaluate case;
in
  builtins.deepSeq result result
