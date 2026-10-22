##! Shared first-party Bazel interfaces; upstream Bazel builders remain separate.
{
  pkgs,
  lib,
  sharedBazelCacheDir ? null,
}: rec {
  mkAosBazelToolchains = import ./toolchains.nix {inherit pkgs lib;};
  aosBazelModules = import ./modules.nix {inherit pkgs lib;};
  aosBazelToolchains = mkAosBazelToolchains {};
  aosBazelRepositories = import ./repositories.nix {
    inherit pkgs lib;
    modules = aosBazelModules;
  };
  mkAosBazelWorkspace = import ./workspace.nix {
    inherit pkgs lib;
    modules = aosBazelModules;
    defaultToolchains = aosBazelToolchains;
    defaultRepositories = aosBazelRepositories;
  };
  mkAosBazelBuild = import ./build.nix {inherit pkgs lib sharedBazelCacheDir;};
  mkAosBazelPackage = import ./package.nix {inherit pkgs lib;};
  mkAosBazelCheck = arguments: mkAosBazelBuild (arguments // {command = "test";});
  aosBazelWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates" "native" "tools/bazel"];
  };
  mkAosBazelShell = {workspace ? aosBazelWorkspace}:
    (import ./development.nix {inherit pkgs lib workspace;}).shell;
  aosBazelLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelWorkspace;
    }).launcher;
}
