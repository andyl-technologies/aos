{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  daemonRunState = "${repoRootString}/crates/crucible/control/crucible-daemon/run-state";
in
  builtins.path {
    path = repoRoot;
    name = "crucible-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base
      != ".git"
      && base != ".crucible"
      && base != "target"
      && base != "__pycache__"
      && !lib.hasSuffix ".pyc" base
      && pathString != "${repoRootString}/result"
      && pathString != daemonRunState
      && !lib.hasPrefix "${daemonRunState}/" pathString
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/AGENTS.md"
        || pathString == "${repoRootString}/default.nix"
        || pathString == "${repoRootString}/LICENSE"
        || pathString == "${repoRootString}/LICENSES"
        || lib.hasPrefix "${repoRootString}/LICENSES" pathString
        || pathString == "${repoRootString}/README.md"
        || pathString == "${repoRootString}/CONTRIBUTING.md"
        || lib.hasPrefix "${repoRootString}/crates" pathString
        || pathString == "${repoRootString}/api"
        || lib.hasPrefix "${repoRootString}/api/proto" pathString
        || lib.hasPrefix "${repoRootString}/docs" pathString
        || pathString == "${repoRootString}/pkgs"
        || pathString == "${repoRootString}/pkgs/default.nix"
        || pathString == "${repoRootString}/pkgs/emulation"
        || pathString == "${repoRootString}/pkgs/emulation/crucible-qemu-plugin.nix"
        || pathString == "${repoRootString}/pkgs/emulation/qemu.nix"
        || pathString == "${repoRootString}/pkgs/emulation/qemu-patches"
        || lib.hasPrefix "${repoRootString}/pkgs/emulation/qemu-patches" pathString
        || pathString == "${repoRootString}/pkgs/kernel"
        || pathString == "${repoRootString}/pkgs/kernel/linux-crucible.nix"
        || pathString == "${repoRootString}/pkgs/kernel/linux.nix"
        || pathString == "${repoRootString}/pkgs/tools"
        || pathString == "${repoRootString}/pkgs/tools/aos-ability-crucible.nix"
        || lib.hasPrefix "${repoRootString}/pkgs/tools/crucible" pathString
        || pathString == "${repoRootString}/stdenv"
        || pathString == "${repoRootString}/stdenv/phases.nix"
        || pathString == "${repoRootString}/modules"
        || pathString == "${repoRootString}/modules/base"
        || pathString == "${repoRootString}/modules/base/build.nix"
        || pathString == "${repoRootString}/modules/profiles"
        || pathString == "${repoRootString}/modules/profiles/ability-crucible.nix"
        || pathString == "${repoRootString}/tests"
        || lib.hasPrefix "${repoRootString}/tests/crucible" pathString
      );
  }
