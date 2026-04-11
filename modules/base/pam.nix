##! modules/base/pam.nix — PAM configuration routing
##!
##! Symlinks the systemd-user PAM config shipped by the systemd package
##! into /etc/pam.d/systemd-user so systemd-logind finds it at runtime.
##! systemd's meson build installs this file under
##! ${pkgs.systemd}/lib/pam.d/systemd-user when -Dpam=enabled. Without
##! the /etc symlink, logind fails to open user sessions and pam_systemd
##! returns PAM_SESSION_ERR.
##!
##! Note: systemd 259 installs PAM drop-ins under libdir/pam.d (not
##! sysconfdir/pam.d as some older docs and earlier versions did). The
##! spec's original path (etc/pam.d/systemd-user) is wrong for 259.1;
##! the actual shipped file is at lib/pam.d/systemd-user.
##!
##! Deployments that need to customize the systemd-user config can
##! override `aos.pam.systemdUserSource` to point at a locally
##! maintained file.
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.pam;
in
{
  options.aos.pam = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to install /etc/pam.d/systemd-user. Required when
        systemd is built with -Dpam=enabled.
      '';
    };

    systemdUserSource = lib.mkOption {
      type = lib.types.path;
      default = "${pkgs.systemd}/lib/pam.d/systemd-user";
      description = ''
        Source path for the systemd-user PAM config file. Defaults to
        the file shipped by the systemd package at
        ''${pkgs.systemd}/lib/pam.d/systemd-user (systemd 259 installs
        PAM drop-ins under libdir/pam.d, not sysconfdir/pam.d).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."pam.d/systemd-user" = {
      source = cfg.systemdUserSource;
    };
  };
}
