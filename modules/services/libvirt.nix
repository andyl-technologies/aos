##! Applies host policy required by the Libvirt service cohort.
{
  config,
  lib,
  ...
}: {
  config = lib.mkIf config.aos.services.libvirt.enable {
    aos.security.polkit.enable = true;
  };
}
