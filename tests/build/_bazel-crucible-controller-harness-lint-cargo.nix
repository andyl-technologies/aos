##! Preserves the full independent Cargo harness-lint execution oracle.
{pkgs}: let
  root = ../..;
  files = directory: let
    entries = builtins.readDir (root + "/${directory}");
  in
    pkgs.lib.concatMap (name: let
      relative = "${directory}/${name}";
    in
      if entries.${name} == "directory"
      then files relative
      else pkgs.lib.optional (entries.${name} == "regular") relative)
    (builtins.attrNames entries);
  extraPaths =
    files "tests/crucible"
    ++ files "docs/rfcs/0010-crucible"
    ++ files "docs/rfcs/0014-signal-driven-fault-model"
    ++ [
      "docs/users/crucible/reference.md"
      "modules/base/build.nix"
      "modules/profiles/ability-crucible.nix"
      "pkgs/default.nix"
      "pkgs/emulation/crucible-qemu-plugin.nix"
      "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch"
      "pkgs/emulation/qemu.nix"
      "pkgs/kernel/linux-crucible.nix"
      "pkgs/kernel/linux.nix"
      "pkgs/tools/aos-ability-crucible.nix"
      "pkgs/tools/crucible-fixtures.nix"
      "pkgs/tools/crucible-fleet-store.nix"
      "pkgs/tools/crucible-guest.nix"
      "pkgs/tools/crucible/_cargo-source.nix"
      "pkgs/tools/crucible/_packages.nix"
      "pkgs/tools/crucible/_release-manifest.nix"
      "pkgs/tools/crucible/_source.nix"
      "pkgs/tools/crucible/crucible.nix"
      "stdenv/phases.nix"
    ];
in
  import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-crucible-controller-harness-lint-cargo-oracle";
    packages = ["crucible-test-support"];
    cargoFlags = ["--test" "harness_lint"];
    captureCompilerArguments = true;
    cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
      inherit (pkgs) lib;
      inherit extraPaths;
    };
  }
