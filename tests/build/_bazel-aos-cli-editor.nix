##! Compares the CLI editor graph and diagnostics with the temporary Cargo oracle.
{
  pkgs,
  fleet ? false,
}: let
  candidate = import ./_bazel-aos-cli.nix {inherit pkgs fleet;};
  cargo = import ./_bazel-aos-cli-cargo.nix {inherit pkgs fleet;};
  profile =
    if fleet
    then "aos-cli-fleet-tests"
    else "aos-cli-tests";
  prefix = "//crates/cli/aos-cli:";
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs rustcFlags;
    # The Cargo editor oracle explicitly applies these flags to execution tools
    # too. Its generator profile differs from ordinary Cargo test builds.
    execRustcFlags = rustcFlags;
    inherit (candidate) packages dependencyPackages repositories;
    inherit (cargo.passthru.editorInputs) cargoSource cargoSetup nativeLibraries nativeTools;
    pname = "aos-bazel-${profile}-editor-checkpoint";
    dependencyProfile = profile;
    sourceInventory = null;
    extraSourceDirectories = ["api/proto"] ++ builtins.attrValues candidate.dependencyPackages;
    packageTargets.aos-cli = {
      root = "lib";
      unit = "unit";
      doctest = null;
    };
    extraTests = map (name: prefix + "bin_" + name) candidate.selectedBins;
    extraEditorTargets = map (name: prefix + "bin_" + name + "_binary") candidate.selectedBins;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorCargoFlags = pkgs.lib.optionals fleet ["--features" "release-fleet-fixture"];
    excludedEditorBins = pkgs.lib.optionals (!fleet) ["aos-release-fleet-fixture" "aos-ability-interruption-audit" "aos-ability-authority-audit"];
    editorDiagnosticContext = true;
  };
in {
  inherit (family) editor editor-cargo-oracle editor-parity;
  editor-workspace = family.workspace;
}
