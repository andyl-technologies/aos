##! modules/services/dbus.nix — D-Bus system message bus
##!
##! dbus 1.14 only ships a user unit (`lib/systemd/user/dbus.service`);
##! the system dbus.service is by convention distro-provided. Systemd's
##! `systemd-logind`, `systemd-hostnamed`, etc. all connect to
##! `/run/dbus/system_bus_socket` and refuse to start if it's absent —
##! that's exactly task #18's symptom.
##!
##! This module contributes:
##!   * `aos.users.users.messagebus` + group (dbus's default runtime user)
##!   * `systemd.sockets.dbus` listening on /run/dbus/system_bus_socket
##!   * `systemd.services.dbus` running dbus-daemon --system
##!   * tmpfiles entry so /run/dbus exists with the right perms
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.dbus;
in {
  options.aos.services.dbus.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = ''
      Run the system D-Bus message bus. Needed for systemd-logind,
      hostnamed, timedated, and every other daemon that publishes or
      consumes the /run/dbus/system_bus_socket.
    '';
  };

  config = lib.mkIf cfg.enable {
    # Standard dbus runtime account. UID 81 matches Debian/Fedora
    # convention so hand-debugged systems look familiar.
    aos.users.users.messagebus = {
      uid = 81;
      group = "messagebus";
      home = "/var/run/dbus";
      shell = "/sbin/nologin";
      description = "D-Bus Message Bus";
      extraGroups = [];
    };
    aos.users.groups.messagebus = {
      gid = 81;
      members = [];
    };

    # dbus's shipped share/dbus-1/system.conf contains:
    #   <include ignore_missing="yes">/etc/dbus-1/system.conf</include>
    # to let admins override. If we symlinked that same file back at
    # /etc/dbus-1/system.conf, the parser would self-include and
    # abort with "Circular inclusion". We therefore do NOT create
    # /etc/dbus-1/system.conf — ignore_missing=yes makes the include
    # a no-op, and dbus-daemon reads the store copy via --config-file
    # on the ExecStart.
    #
    # system.d is an include *directory* for drop-in policy files;
    # the store copy exists next to system.conf and the shipped
    # system.conf's `<includedir>system.d</includedir>` resolves
    # relative to its own directory, so no symlink needed there
    # either.
    #
    # If you want to add a local override, create /etc/dbus-1/system.conf
    # and include the store copy explicitly:
    #   <include>${pkgs.dbus}/share/dbus-1/system.conf</include>

    # /run/dbus needs to exist before dbus-daemon starts (it creates
    # the socket file there). tmpfiles runs early in stage 2.
    environment.etc."tmpfiles.d/dbus.conf".text = ''
      d /run/dbus 0755 root root -
      d /var/lib/dbus 0755 root root -
    '';

    systemd.services."dbus" = {
      description = "D-Bus System Message Bus";
      wantedBy = ["multi-user.target"];
      after = [
        "local-fs.target"
        "systemd-tmpfiles-setup.service"
      ];
      requires = ["systemd-tmpfiles-setup.service"];
      serviceConfig = {
        RuntimeDirectory = "dbus";
        RuntimeDirectoryMode = "0755";
        # --nofork + Type=simple so systemd tracks dbus-daemon's PID
        # directly (no double-fork races). dbus-daemon binds the
        # socket path from system.conf itself — no systemd socket
        # activation, since that needs --address=systemd: which also
        # needs LISTEN_FDS which is fragile to wire up correctly.
        Type = "simple";
        ExecStart = "${pkgs.dbus}/bin/dbus-daemon --nofork --nopidfile --config-file=${pkgs.dbus}/share/dbus-1/system.conf";
        ExecReload = "${pkgs.dbus}/bin/dbus-send --print-reply --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig";
        OOMScoreAdjust = "-900";
        Restart = "on-failure";
        RestartSec = "5s";
      };
      # Alias for legacy clients that look up messagebus.service.
      aliases = ["messagebus.service"];
    };
  };
}
