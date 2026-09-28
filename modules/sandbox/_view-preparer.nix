##! Immutable entrypoint rendering for the existing checked view scripts.
{
  config,
  pkgs,
}: let
  confined = config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0";
  tools = pkgs.aos-sandbox-view-preparer-tools;
in {
  inherit confined;

  coreutils =
    if confined
    then "${tools}/libexec"
    else "${pkgs.coreutils}/bin";
  utilLinux =
    if confined
    then "${tools}/libexec"
    else "${pkgs.util-linux}/bin";

  writeScript = name: text:
    if confined
    then
      pkgs.writeTextFile {
        inherit name;
        executable = true;
        destination = "/bin/${name}";
        text = ''
          #!${tools}/libexec/bash
          ${text}
        '';
        checkPhase = ''
          ${pkgs.buildPackages.bash}/bin/bash -n "$target"
        '';
        meta.mainProgram = name;
      }
    else pkgs.writeShellScriptBin name text;

  serviceConfig = {
    # Bash must never interpret an administrator/environment-selected prelude
    # before reaching the immutable script. These are not caller arguments.
    UnsetEnvironment = ["BASH_ENV" "ENV" "SHELLOPTS" "BASHOPTS" "CDPATH" "GLOBIGNORE" "LD_PRELOAD" "LD_LIBRARY_PATH"];
    Environment = ["LC_ALL=C"];
  };
}
