##! Qualifies the runtime-independent Worker graph under both feature selections.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-worker-inventory.json,
}: let
  configuration = allFeatures: import ./_bazel-hub-worker.nix {inherit pkgs sourceInventory allFeatures;};
  default = configuration false;
  all-features = configuration true;
in
  default
  // {
    inherit default all-features;
    all =
      pkgs.runCommand "aos-bazel-hub-worker-all-configurations" {
        buildDeps = [default.all default.editor-parity all-features.all all-features.editor-parity];
      } ''
        mkdir -p "$out/default" "$out/all-features"
        cp -r ${default.all}/. "$out/default/"
        cp -r ${all-features.all}/. "$out/all-features/"
        cp ${default.editor-parity}/parity.json "$out/default/editor-parity.json"
        cp ${all-features.editor-parity}/parity.json "$out/all-features/editor-parity.json"
      '';
  }
