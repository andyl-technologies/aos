##! Qualifies production and purpose-built Worker deployments independently.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-worker-wasm-inventory.json,
}: let
  configuration = featureSet: import ./_bazel-hub-worker-wasm.nix {inherit pkgs sourceInventory featureSet;};
  default = configuration "default";
  do-e2e = configuration "do-e2e";
  all-features = configuration "all-features";
in
  default
  // {
    inherit default do-e2e all-features;
    all =
      pkgs.runCommand "aos-bazel-hub-worker-wasm-all-configurations" {
        buildDeps = [default.all do-e2e.all all-features.all];
      } ''
        mkdir -p "$out"
        cp -r ${default.all} "$out/default"
        cp -r ${do-e2e.all} "$out/do-e2e"
        cp -r ${all-features.all} "$out/all-features"
      '';
  }
