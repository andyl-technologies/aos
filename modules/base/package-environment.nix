##! Makes installed user and system packages available to login sessions.
{
  config,
  lib,
  pkgs,
  ...
}: let
  basePath = lib.removePrefix "/run/wrappers/bin:" config.system.build.systemPath;
  sessionPath = user:
    lib.concatStringsSep ":" [
      "/run/wrappers/bin"
      "/var/lib/profiles/per-user/${user}/current/bin"
      "/var/lib/profiles/per-user/${user}/current/sbin"
      "/var/lib/profiles/system-packages/current/bin"
      "/var/lib/profiles/system-packages/current/sbin"
      basePath
    ];
in {
  config = {
    # PAM expands the authenticated account name even for noninteractive SSH.
    environment.sessionVariables.PATH = lib.mkDefault (sessionPath "@{PAM_USER}");

    environment.etc."profile.d/10-apm-path.sh".text = ''
      # Resolve the current account rather than inheriting a caller's USER.
      aos_login_user=$(${pkgs.coreutils}/bin/id -un)
      case "$aos_login_user" in
        ""|*/*|.|..) ;;
        *) export PATH="${sessionPath "$aos_login_user"}" ;;
      esac
      unset aos_login_user
    '';
  };
}
