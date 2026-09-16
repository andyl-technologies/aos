##! Package-owned NSS sources supplied by the selected systemd manager.
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
  source = database: name: order: actions: {
    inherit database order actions;
    source = name;
  };
in {
  config.aos.nsswitch.contributions = lib.mkIf selected {
    systemd-passwd = source "passwd" "systemd" 200 [];
    systemd-group = source "group" "systemd" 200 [
      {
        status = "success";
        action = "merge";
        negated = false;
      }
    ];
    systemd-host-myhostname = source "hosts" "myhostname" 200 [];
    systemd-host-resolve = source "hosts" "resolve" 300 [
      {
        status = "unavail";
        action = "return";
        negated = true;
      }
    ];
  };
}
