##! Realizes the merged native journal policy through configuration files.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.journald;
  policy = {
    inherit (cfg) storage compress;
    max_retention_seconds = cfg.maxRetentionSeconds;
    max_use_bytes = cfg.maxUseBytes;
    max_file_bytes = cfg.maxFileSizeBytes;
    rate_limit_interval_millis = cfg.rateLimitIntervalMillis;
    rate_limit_burst = cfg.rateLimitBurst;
    forward_to_syslog = cfg.forwardToSyslog;
  };
  files = import ./platform/_event-log-configuration.nix {inherit policy;};
in {
  aos.journald.files = files;
  aos.abilities.configuration.operations.file.effects = lib.mapAttrs' (path: file:
    lib.nameValuePair "journald-${builtins.hashString "sha256" path}" {
      input = {
        path = "/etc/${path}";
        content = file.text;
        mode = "0444";
      };
    })
  files;
}
