##! Derives native kernel policy from the final merged hardening settings.
{
  config,
  lib,
  ...
}: {
  config.aos.kernel.sysctl =
    lib.mkIf config.aos.security.hardening.enable
    config.aos.security.hardening.sysctl;
}
