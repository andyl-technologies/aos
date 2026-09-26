##! Provider-neutral event-log policy selection.
{lib, ...}: {
  imports = [./_journald-abilities.nix];

  options.aos.journald = {
    storage = lib.mkOption {
      type = lib.abilities.types.enum ["persistent" "volatile" "automatic"];
      default = "persistent";
      description = "Event-log storage lifetime policy.";
    };
    maxRetentionSeconds = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1;
        maximum = 315576000;
      };
      default = 2592000;
      description = "Maximum event retention in seconds.";
    };
    maxUseBytes = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1048576;
        maximum = 1125899906842624;
      };
      default = 524288000;
      description = "Maximum total persistent event-log storage in bytes.";
    };
    maxFileSizeBytes = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1048576;
        maximum = 1125899906842624;
      };
      default = 52428800;
      description = "Maximum size of one event-log segment in bytes.";
    };
    rateLimitIntervalMillis = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1;
        maximum = 86400000;
      };
      default = 30000;
      description = "Per-source event rate-limit interval in milliseconds.";
    };
    rateLimitBurst = lib.mkOption {
      type = lib.abilities.types.integer {
        minimum = 1;
        maximum = 4294967295;
      };
      default = 10000;
      description = "Maximum events accepted from one source during the rate-limit interval.";
    };
    forwardToSyslog = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = false;
      description = "Forward accepted events to the selected syslog transport when available.";
    };
    compress = lib.mkOption {
      type = lib.abilities.types.boolean;
      default = true;
      description = "Compress retained event-log segments.";
    };
  };
}
