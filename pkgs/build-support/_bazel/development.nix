##! Lightweight development entry points without first-party CLI dependencies.
{
  pkgs,
  lib,
  workspace,
}: let
  launcher = pkgs.writeShellScriptBin "aos-bazel" ''
    exec ${pkgs.python3}/bin/python3 ${../../../tools/bazel/launcher.py} \
      --config ${workspace.configuration} \
      --workspace "''${AOS_DEV_ROOT:?Enter the Bazel shell or use aos-dev bazel}" \
      --output-base "''${AOS_BAZEL_OUTPUT_BASE:?Use aos-dev bazel to select an output base}" \
      --lock ${workspace.preparedLock}/MODULE.bazel.lock --shadow-workspace "$@"
  '';
  devCommand = pkgs.writeShellScriptBin "aos-dev" ''
    exec ${pkgs.bash}/bin/bash "$AOS_DEV_ROOT/tools/dev/aos-dev" "$@"
  '';
in {
  inherit launcher;
  shell = pkgs.mkShell {
    name = "aos-bazel-dev";
    buildDeps = [launcher devCommand pkgs.bazel pkgs.python3 pkgs.bash pkgs.nix pkgs.coreutils pkgs.acl];
    shellHook = ''
      export PATH="${workspace.toolchains}/bin:${workspace.toolchains}/developer/bin:$PATH"
      export AOS_DEV_ROOT="''${AOS_DEV_ROOT:-$PWD}"
    '';
  };
}
