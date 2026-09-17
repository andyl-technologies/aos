##! Package-owned event-log policy requirement.
{
  config,
  lib,
  ...
}: let
  cfg =
    lib.attrByPath ["aos" "journald"] {
      storage = "persistent";
      maxRetentionSeconds = 2592000;
      maxUseBytes = 524288000;
      maxFileSizeBytes = 52428800;
      rateLimitIntervalMillis = 30000;
      rateLimitBurst = 10000;
      forwardToSyslog = false;
      compress = true;
    }
    config;
  interface = lib.abilities.interfaces.eventLogPolicy.interface;
  configured = config.aos.abilities.environment != null;
in {
  config.aos.abilities = {
    requirementTemplates.event-log-policy = {
      description = "Requires an event-log policy implementation.";
      interface = interface.identity.name;
      inherit (interface.identity) abi descriptor;
    };
    instances = lib.mkIf configured {event-log-policy = {};};
    requests = lib.mkIf configured {
      event-log-policy = {
        requirement = "event-log-policy";
        consumer = "event-log-policy";
        scope = ["event-log"];
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
      };
    };
  };
}
