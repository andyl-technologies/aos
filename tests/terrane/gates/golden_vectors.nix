{
  pkgs,
  sourceGate,
  ...
}: let
  consumerFiles = {
    algebra = "algebra-models.nix";
    attribute = "attribute-models.nix";
    collection = "collection-vectors.nix";
    container = "container-models.nix";
    control = "control-models.nix";
    evidence = "evidence-models.nix";
    foundation = "foundation-vectors.nix";
    index = "index-models.nix";
    legacy = "legacy-vectors.nix";
    lineage = "lineage-models.nix";
    namespace = "namespace-models.nix";
    pack = "pack-vectors.nix";
    prefix = "prefix-models.nix";
    publication = "publication-vectors.nix";
    recipe-context = "recipe-context-models.nix";
    recorded-context = "recorded-context-models.nix";
    reconciliation = "reconciliation-models.nix";
    refs = "refs-models.nix";
    retirement = "retirement-models.nix";
  };

  consumers = builtins.mapAttrs (_: file: import (../. + "/${file}") {inherit sourceGate;}) consumerFiles;
  names = builtins.attrNames consumers;
  inventory = sourceGate "golden-vector-inventory" ''
    python3 tests/terrane/golden_inventory.py \
      docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      ${builtins.concatStringsSep " " names} > "$out/result"
  '';

  requireResult = name: ''
    test -s ${consumers.${name}}/result
  '';
in {
  # The complete gate requires every owning suite. Missing current-milestone
  # templates fail their individual checks instead of disappearing from the set.
  golden-vectors = pkgs.mkDerivation {
    pname = "terrane-gate-golden-vectors";
    version = "0.1.0";
    src = null;
    buildDeps = [inventory] ++ builtins.attrValues consumers;
    phases = [
      {
        name = "check";
        script = ''
          test -s ${inventory}/result
          ${builtins.concatStringsSep "\n" (map requireResult names)}
          mkdir -p "$out"
          cp ${inventory}/result "$out/inventory"
          printf 'PASS: complete published golden inventory and %s mandatory owning suites\n' \
            ${toString (builtins.length names)} > "$out/result"
        '';
      }
    ];
  };
}
