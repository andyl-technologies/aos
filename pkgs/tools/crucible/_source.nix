{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
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
      && base != "target"
      && base != "result"
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/CLAUDE.md"
        || pathString == "${repoRootString}/AGENTS.md"
        || pathString == "${repoRootString}/LICENSE"
        || pathString == "${repoRootString}/LICENSES"
        || lib.hasPrefix "${repoRootString}/LICENSES" pathString
        || pathString == "${repoRootString}/LICENSING.md"
        || pathString == "${repoRootString}/README.md"
        || pathString == "${repoRootString}/CONTRIBUTING.md"
        || pathString == "${repoRootString}/CONTRIBUTOR_LICENSE_AGREEMENT.md"
        || lib.hasPrefix "${repoRootString}/crates" pathString
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
        || lib.hasPrefix "${repoRootString}/pkgs/tools/crucible" pathString
        || pathString == "${repoRootString}/modules"
        || pathString == "${repoRootString}/modules/base"
        || pathString == "${repoRootString}/modules/base/build.nix"
        || pathString == "${repoRootString}/tests"
        || lib.hasPrefix "${repoRootString}/tests/crucible" pathString
      );
  }
