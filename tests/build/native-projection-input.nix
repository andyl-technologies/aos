##! Keeps projection source identity while excluding unselected payload outputs.
{
  lib,
  pkgs,
}: let
  package = pkgs.mkDerivation {
    pname = "native-projection-payload";
    version = "1";
    src = null;
    module = ../effects/package-interface;
    outputs = ["out" "unused"];
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out" "$unused"'';
      }
    ];
  };
  descriptor = retainPayloads:
    lib.build.evaluationInput {
      inherit lib pkgs retainPayloads;
      packages = [package];
      scope = ["projection-check"];
      system = pkgs.stdenv.hostPlatform.system;
    };
  full = descriptor true;
  projection = descriptor false;
  inventory = root: (lib.build.closureInfo {inherit pkgs;}) {rootPaths = [root];};
  fullInventory = inventory full;
  projectionInventory = inventory projection;
in
  pkgs.mkDerivation {
    pname = "native-projection-input-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.jq fullInventory projectionInventory];
    phases = [
      {
        name = "check";
        script = ''
          ${pkgs.jq}/bin/jq -en --slurpfile full ${full} --slurpfile projection ${projection} \
            '$full == $projection' >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            'any(.paths[]; .path == $payload) and (all(.paths[]; .path != $unused))' \
            ${fullInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            --arg source ${lib.escapeShellArg (toString package.module)} \
            'all(.paths[]; .path != $payload and .path != $unused) and any(.paths[]; .path == $source)' \
            ${projectionInventory}/inventory.json >/dev/null
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
