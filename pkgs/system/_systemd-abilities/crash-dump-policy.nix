##! Realizes native crash-dump policy using the retained systemd backend.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.security.hardening;
  rendered = import ./platform/_crash-dump-configuration.nix {
    systemd = package;
    coreutils = dependencies.coreutils;
    policy.enabled = cfg.coreDump.enable;
  };
in {
  config = lib.mkIf cfg.enable {
    aos.security.hardening.crashFiles = rendered.etc;
    aos.kernel.sysctl."kernel.core_pattern" = rendered.corePattern;
    aos.abilities.configuration.operations.file.effects.coredump-policy.input = {
      path = "/etc/systemd/coredump.conf";
      content = rendered.etc."systemd/coredump.conf".text;
      mode = "0444";
    };
  };
}
