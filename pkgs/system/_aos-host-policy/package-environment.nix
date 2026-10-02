##! Adds installed user and system packages to authenticated login sessions.
{
  config,
  lib,
  dependencies ? {},
  package ? null,
  ...
}: let
  # Login follows the activated profile rather than image-only package paths.
  basePath = "/var/lib/profiles/system/current/bin:/var/lib/profiles/system/current/sbin";
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
  config = lib.optionalAttrs (package != null) (lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    environment.sessionVariables.PATH = lib.mkDefault (sessionPath "@{PAM_USER}");
    aos.abilities.configuration.operations.file.effects.login-package-path.input = {
      path = "/etc/profile.d/10-apm-path.sh";
      mode = "0644";
      content = ''
        # Resolve the current account rather than inheriting a caller's USER.
        aos_login_user=$(${dependencies.coreutils}/bin/id -un)
        case "$aos_login_user" in
          ""|*/*|.|..) ;;
          *) export PATH="${sessionPath "$aos_login_user"}" ;;
        esac
        unset aos_login_user
      '';
    };
  });
}
