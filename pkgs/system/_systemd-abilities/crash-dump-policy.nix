##! Realizes native crash-dump policy using the retained systemd backend.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.security.hardening;
  containerTarget = config.aos.initSystem.container or false;
  hostStage = (config.aos.boot.stage or "host") == "host";
  rendered = import ./platform/_crash-dump-configuration.nix {
    systemd = package;
    coreutils = dependencies.coreutils;
    policy.enabled = cfg.coreDump.enable;
  };
in {
  config = lib.mkIf cfg.enable {
    aos.security.hardening.crashFiles = lib.mkIf hostStage rendered.etc;
    # The runtime owns host-wide crash routing unless a collector is requested.
    aos.kernel.sysctl = lib.mkIf (!containerTarget || cfg.coreDump.enable) {
      "kernel.core_pattern" = rendered.corePattern;
    };
    aos.abilities.configuration.operations.file.effects.coredump-policy = lib.mkIf hostStage {
      input = {
        path = "/etc/systemd/coredump.conf";
        content = rendered.etc."systemd/coredump.conf".text;
        mode = "0444";
      };
    };
  };
}
