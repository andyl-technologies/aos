{
  lib,
  includeIntegrationInputs ? false,
}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
in
  builtins.path {
    path = repoRoot;
    name = "aos-workspace-src";
    filter = path: type: let
      pathString = toString path;
      base = baseNameOf path;
      generatedDir =
        type
        == "directory"
        && (
          base
          == ".git"
          || base == ".direnv"
          || base == ".worktrees"
          || base == "result"
          || lib.hasPrefix "result-" base
          || base == "target"
          || lib.hasPrefix "target-" base
        );
      # Cargo builds need the workspace, JSON fixtures included by Rust tests,
      # and API manifests consumed by build scripts. Nix-only test edits must
      # not rebuild every Rust provider.
      workspaceInput =
        pathString
        == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/tests"
        || pathString == "${repoRootString}/tests/abilities"
        || pathString == "${repoRootString}/tests/abilities/fixtures"
        || lib.hasPrefix "${repoRootString}/tests/abilities/fixtures/" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString;
      # The aos integration-test package evaluates repository Nix modules and
      # must retain their exact source alongside the Cargo workspace.
      integrationInput =
        lib.hasPrefix "${repoRootString}/lib" pathString
        || lib.hasPrefix "${repoRootString}/modules" pathString
        || lib.hasPrefix "${repoRootString}/pkgs" pathString
        || lib.hasPrefix "${repoRootString}/qualification" pathString
        || lib.hasPrefix "${repoRootString}/stdenv" pathString
        || lib.hasPrefix "${repoRootString}/systems" pathString
        || lib.hasPrefix "${repoRootString}/tests/abilities" pathString
        || lib.hasPrefix "${repoRootString}/tests/build" pathString
        || lib.hasPrefix "${repoRootString}/tests/fleet" pathString
        || lib.hasPrefix "${repoRootString}/tests/qualification" pathString
        || lib.hasPrefix "${repoRootString}/tests/vm" pathString
        || pathString == "${repoRootString}/tests/native"
        || pathString == "${repoRootString}/tests/native/hub-settings.py"
        || pathString == "${repoRootString}/default.nix"
        || pathString == "${repoRootString}/flake.nix"
        || pathString == "${repoRootString}/justfile";
    in
      !generatedDir
      && (workspaceInput || (includeIntegrationInputs && integrationInput));
  }
