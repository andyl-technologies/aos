##! Pins configuration commands without depending on their consuming package.
{
  pkgs,
  lib,
}: let
  packageRuntime = pkgs.aos.packageRuntime;
  environment = import ../../boot/_aos-configuration-lower/cargo-env.nix {
    inherit (pkgs) erofs-utils util-linux;
    inherit packageRuntime;
  };
  tools = [pkgs.erofs-utils pkgs.util-linux packageRuntime];
in
  pkgs.mkDerivation {
    pname = "aos-bazel-configuration-tools";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.jq];
    outputChecks.out = {};
    exportReferencesGraph.tools = tools;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          jq -cS '{schema: 1, closure: [.tools[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
          cat > "$out/configuration.env" <<'ENVIRONMENT'
          ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name}=${value}") environment)}
          ENVIRONMENT
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files([
              "configuration.env",
              "closure.json",
          ], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
