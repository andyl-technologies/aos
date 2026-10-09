##! Package-owned systemd service accounts.
{
  config,
  lib,
  ...
}: let
  systemdUsers = {
    systemd-journal = {
      uid = 190;
      group = "systemd-journal";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Journal";
      extraGroups = [];
    };
    systemd-timesync = {
      uid = 194;
      group = "systemd-timesync";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Time Synchronization";
      extraGroups = [];
    };
    systemd-oom = {
      uid = 195;
      group = "systemd-oom";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Userspace OOM Killer";
      extraGroups = [];
    };
    systemd-coredump = {
      uid = 196;
      group = "systemd-coredump";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Core Dumper";
      extraGroups = [];
    };
  };
  systemdGroups =
    builtins.mapAttrs (_: user: {
      gid = user.uid;
      members = [];
    })
    systemdUsers;
in {
  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    aos.users.users = systemdUsers;
    aos.users.groups = systemdGroups;
  };
}
