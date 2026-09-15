##! tests/abilities/conformance/direct.nix - One direct Nix corpus evaluation.
{
  caseJson,
  system,
}: let
  lib = import ./lib {inherit system;};
  case = builtins.fromJSON caseJson;
  result = lib.abilities.schemas.checkValue case.schema case.value;
in
  builtins.deepSeq result result
