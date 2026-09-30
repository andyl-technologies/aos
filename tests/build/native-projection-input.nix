##! Keeps projection source identity while excluding unselected payload outputs.
{
  lib,
  pkgs,
}: let
  schema = pkgs.mkDerivation {
    pname = "native-projection-schema";
    version = "1";
    src = null;
    module = ../../pkgs/tools/_aos-metadata-provider/facts;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  package = pkgs.mkDerivation {
    pname = "native-projection-payload";
    version = "1";
    src = null;
    module = ../effects/package-interface;
    moduleDeps = [schema];
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
            '$full == $projection and ($projection[0].moduleEnvelopes | keys) == ["native-projection-payload", "native-projection-schema"]' >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            'any(.paths[]; .path == $payload) and (all(.paths[]; .path != $unused))' \
            ${fullInventory}/inventory.json >/dev/null
          ${pkgs.jq}/bin/jq -e --arg payload ${lib.escapeShellArg (toString package)} \
            --arg unused ${lib.escapeShellArg (toString package.unused)} \
            --arg source ${lib.escapeShellArg (toString package.module)} \
            --arg schemaPayload ${lib.escapeShellArg (toString schema)} \
            --arg schemaSource ${lib.escapeShellArg (toString schema.module)} \
            --arg envelope ${lib.escapeShellArg (toString package.deploymentArtifact)} \
            --arg schemaEnvelope ${lib.escapeShellArg (toString schema.deploymentArtifact)} \
            'all(.paths[]; .path != $payload and .path != $unused and .path != $schemaPayload)
              and any(.paths[]; .path == $source)
              and any(.paths[]; .path == $schemaSource)
              and any(.paths[]; .path == $envelope)
              and any(.paths[]; .path == $schemaEnvelope)' \
            ${projectionInventory}/inventory.json >/dev/null
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
