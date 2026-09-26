##! Renders one selected event-log policy into systemd-owned configuration.
{policy}: let
  yesNo = value:
    if value
    then "yes"
    else "no";
  storage =
    if policy.storage == "automatic"
    then "auto"
    else policy.storage;
in
  {
    "systemd/journald.conf".text = ''
      # Generated from the selected event-log-policy ability request.
      [Journal]
      Storage=${storage}
      MaxRetentionSec=${toString policy.max_retention_seconds}s
      SystemMaxUse=${toString policy.max_use_bytes}
      SystemMaxFileSize=${toString policy.max_file_bytes}
      RateLimitIntervalSec=${toString policy.rate_limit_interval_millis}ms
      RateLimitBurst=${toString policy.rate_limit_burst}
      ForwardToSyslog=${yesNo policy.forward_to_syslog}
      Compress=${yesNo policy.compress}
    '';
  }
  // (
    if policy.storage == "volatile"
    then {}
    else {
      "tmpfiles.d/aos-event-log.conf".text = ''
        # The selected systemd event-log implementation owns this directory.
        d /var/log/journal 2755 root systemd-journal -
      '';
    }
  )
