##! Qualifies Native defaults and every optional Hub service feature.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-service-inventory.json,
}: let
  mkConfiguration = allFeatures:
    import ./_bazel-hub-service-configuration.nix {
      inherit pkgs sourceInventory allFeatures;
    };
  default = mkConfiguration false;
  all-features = mkConfiguration true;
in
  default
  // {
    inherit default all-features;
    all =
      pkgs.runCommand "aos-bazel-hub-service-all-configurations" {
        buildDeps = [default.all all-features.all];
      } ''
        mkdir -p "$out"
        cp -r ${default.all} "$out/default"
        cp -r ${all-features.all} "$out/all-features"
      '';
  }
