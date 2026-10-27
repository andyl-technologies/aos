##! Preserves the independent Cargo campaign traceability audit oracle.
{pkgs}: let
  root = ../..;
  files = directory: suffixes: let
    entries = builtins.readDir (root + "/${directory}");
    selected =
      builtins.filter
      (name:
        entries.${name}
        == "regular"
        && builtins.any (suffix: pkgs.lib.hasSuffix suffix name) suffixes)
      (builtins.attrNames entries);
  in
    map (name: directory + "/" + name)
    selected;
  # The audit compiles RFC text and native-runner fixtures into its oracle and
  # reads registered Nix flights at runtime. Keep these explicit source inputs.
  extraPaths =
    files "docs/rfcs/0020-crucible-campaigns" [".md" ".tsv"]
    ++ files "tests/crucible" [".nix" ".sh" ".toml"]
    ++ [
      "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch"
      "pkgs/emulation/qemu-patches/_atomic-patch.nix"
    ];
in
  import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-crucible-controller-campaign-cargo-oracle";
    packages = ["crucible-test-support"];
    cargoFlags = ["--test" "campaign_gate_traceability"];
    captureCompilerArguments = true;
    cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
      inherit (pkgs) lib;
      inherit extraPaths;
    };
  }
