##! Package-owned systemd service accounts.
{
  abilitySelection ? null,
  lib,
  ...
}: let
  managerBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "system-manager";
  selected =
    builtins.length managerBindings == 1
    && (builtins.head managerBindings).binding.request == "system:manager";
  systemdUsers = {
    systemd-journal = {
      uid = 190;
      group = "systemd-journal";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Journal";
      extraGroups = [];
    };
    systemd-network = {
      uid = 192;
      group = "systemd-network";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Network Management";
      extraGroups = [];
    };
    systemd-resolve = {
      uid = 193;
      group = "systemd-resolve";
      home = "/";
      shell = "/sbin/nologin";
      description = "systemd Resolver";
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
  systemdGroups = builtins.mapAttrs (_: user: {
    gid = user.uid;
    members = [];
  }) systemdUsers;
in {
  config = lib.mkIf selected {
    aos.users.users = systemdUsers;
    aos.users.groups = systemdGroups;
  };
}
