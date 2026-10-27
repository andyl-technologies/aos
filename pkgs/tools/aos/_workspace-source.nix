{
  lib,
  includeIntegrationInputs ? false,
  selectedCrates ? null,
  extraPaths ? [],
}: let
  isCargoBuildDirectory = import ../../build-support/_cargo-build-directory.nix;
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  cratesRoot = "${repoRootString}/crates";
  # A migrated worktree can retain local state beneath the retired flat crate.
  # Neither that directory nor the current daemon's run state is package source.
  daemonLocalStatePaths = [
    "${cratesRoot}/crucible-daemon"
    "${cratesRoot}/crucible/crucible-daemon/run-state"
  ];
  selectedCrateInput = pathString:
    pathString
    == cratesRoot
    || pathString == "${cratesRoot}/Cargo.toml"
    || pathString == "${cratesRoot}/Cargo.lock"
    || builtins.any
    (crate: let
      selectedPath = "${cratesRoot}/${crate}";
    in
      pathString
      == selectedPath
      || lib.hasPrefix "${selectedPath}/" pathString
      # Nested workspace members need every ancestor retained for traversal.
      || lib.hasPrefix "${pathString}/" selectedPath)
    selectedCrates;
  extraInput = pathString:
    builtins.any (relative: let
      selectedPath = "${repoRootString}/${relative}";
    in
      pathString
      == selectedPath
      || lib.hasPrefix "${selectedPath}/" pathString
      || lib.hasPrefix "${pathString}/" selectedPath)
    extraPaths;
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
          || base == "__pycache__"
          || isCargoBuildDirectory repoRoot path
        );
      # Nix out-links are symlinks. Ordinary Rust module directories may be
      # named result; pruning them would silently remove package source.
      generatedResult =
        type
        == "symlink"
        && (base == "result" || lib.hasPrefix "result-" base);
      # Cargo builds need the workspace, JSON fixtures included by Rust tests,
      # and API manifests consumed by build scripts. Nix-only test edits must
      # not rebuild every Rust provider.
      workspaceInput =
        pathString
        == repoRootString
        || (
          if selectedCrates == null
          then lib.hasPrefix cratesRoot pathString
          else selectedCrateInput pathString
        )
        || extraInput pathString
        || (selectedCrates == null && (pathString == "${repoRootString}/api" || lib.hasPrefix "${repoRootString}/api/proto" pathString))
        || pathString == "${repoRootString}/tests"
        || pathString == "${repoRootString}/tests/abilities"
        || pathString == "${repoRootString}/tests/abilities/fixtures"
        || lib.hasPrefix "${repoRootString}/tests/abilities/fixtures/" pathString
        || (
          selectedCrates
          == null
          && (
            pathString
            == "${repoRootString}/docs"
            || pathString == "${repoRootString}/docs/rfcs"
            || lib.hasPrefix "${repoRootString}/docs/rfcs/0012-hub-surface-topology" pathString
            || lib.hasPrefix "${repoRootString}/docs/rfcs/0025-crucible-node-contract" pathString
          )
        );
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
      && !generatedResult
      # Local Python bytecode depends on host tooling, not package source.
      && !lib.hasSuffix ".pyc" base
      && !lib.hasSuffix ".pyo" base
      && !builtins.any (localState: pathString == localState || lib.hasPrefix "${localState}/" pathString) daemonLocalStatePaths
      && (workspaceInput || (includeIntegrationInputs && integrationInput));
  }
