##! Ensures declared propagated dependencies survive as package-store references.
{pkgs}: let
  fixture = pkgs.mkDerivation {
    pname = "propagated-dependency-closure-fixture";
    version = "0";
    src = null;
    outputs = ["out" "dev"];
    propagatedDeps = [pkgs.zlib];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out" "$dev"
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "propagated-dependency-closure-check";
    version = "0";
    src = null;
    outputChecks = {};
    buildDeps = [pkgs.jq];
    exportReferencesGraph.out = [fixture];
    exportReferencesGraph.dev = [fixture.dev];
    phases = [
      {
        name = "check";
        script = ''
          set -eu

          jq -e --arg dependency '${pkgs.zlib}' \
            '.out[] | select(.path == $dependency)' \
            "$NIX_ATTRS_JSON_FILE" >/dev/null
          jq -e --arg dependency '${pkgs.zlib}' \
            '.dev[] | select(.path == $dependency)' \
            "$NIX_ATTRS_JSON_FILE" >/dev/null

          test "$(cat ${fixture}/nix-support/propagated-build-inputs)" = '${pkgs.zlib}'
          test "$(cat ${fixture.dev}/nix-support/propagated-build-inputs)" = '${pkgs.zlib}'

          mkdir -p "$out"
          printf '%s\n' "propagated dependency closure passed" > "$out/result"
        '';
      }
    ];
  }
