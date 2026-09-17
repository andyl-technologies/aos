##! Provider-neutral event-log policy selection.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.journald;
  interface = lib.abilities.interfaces.eventLogPolicy.interface;
  parameters = {
    inherit (cfg) storage;
    max_retention_seconds = cfg.maxRetentionSeconds;
    max_use_bytes = cfg.maxUseBytes;
    max_file_bytes = cfg.maxFileSizeBytes;
    rate_limit_interval_millis = cfg.rateLimitIntervalMillis;
    rate_limit_burst = cfg.rateLimitBurst;
    forward_to_syslog = cfg.forwardToSyslog;
    compress = cfg.compress;
  };
in {
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

  config.aos.abilities = {
    instances."event-log:policy" = {};
    requirementTemplates."event-log:policy" = {
      description = "Requires an event-log policy implementation.";
      interface = interface.identity.name;
      inherit (interface.identity) abi descriptor;
    };
    requests."event-log:policy" = {
      requirement = "event-log:policy";
      consumer = "event-log:policy";
      scope = ["event-log"];
      inherit parameters;
    };
  };
}
