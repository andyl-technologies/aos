##! Provider-neutral event-log policy selection.
{lib, ...}: {
  options.aos.journald = {
    files = lib.mkOption {
      extensible = true;
      type = lib.types.attrsOf (lib.types.submodule {options.text = lib.mkOption {type = lib.types.lines;};});
      default = {};
      readOnly = true;
      description = "Files derived by the selected native journal backend.";
    };
    storage = lib.mkOption {
      type = lib.types.enum ["persistent" "volatile" "automatic"];
      default = "persistent";
      description = "Event-log storage lifetime policy.";
    };
    maxRetentionSeconds = lib.mkOption {
      type = lib.types.ints.between 1 315576000;
      # Preserve the former systemd "1month" retention interval exactly.
      default = 2629800;
      description = "Maximum event retention in seconds.";
    };
    maxUseBytes = lib.mkOption {
      type = lib.types.ints.between 1048576 1125899906842624;
      default = 524288000;
      description = "Maximum total persistent event-log storage in bytes.";
    };
    maxFileSizeBytes = lib.mkOption {
      type = lib.types.ints.between 1048576 1125899906842624;
      default = 52428800;
      description = "Maximum size of one event-log segment in bytes.";
    };
    rateLimitIntervalMillis = lib.mkOption {
      type = lib.types.ints.between 1 86400000;
      default = 30000;
      description = "Per-source event rate-limit interval in milliseconds.";
    };
    rateLimitBurst = lib.mkOption {
      type = lib.types.ints.between 1 4294967295;
      default = 10000;
      description = "Maximum events accepted from one source during the rate-limit interval.";
    };
    forwardToSyslog = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Forward accepted events to the selected syslog transport when available.";
    };
    compress = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Compress retained event-log segments.";
    };
  };
}
