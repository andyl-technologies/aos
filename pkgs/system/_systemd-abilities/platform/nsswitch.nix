##! Package-owned NSS sources supplied by the selected systemd manager.
{lib, ...}: let
  source = database: name: order: actions: {
    inherit database order actions;
    source = name;
  };
in {
  config.aos.nsswitch.sources = {
    systemd-passwd = source "passwd" "systemd" 200 [];
    systemd-group = source "group" "systemd" 200 [];
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
