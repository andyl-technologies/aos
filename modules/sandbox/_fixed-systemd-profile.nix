##! Requires the canonical PID 1 build for the selected sandbox kernel profile.
{
  config,
  pkgs,
}:
# mkSystem binds this package set's sole Systemd to the actual boot kernel.
# The paid native kernel-notes comparison remains independently mandatory.
config.aos.manager.selected
!= null
&& config.aos.manager.selected.name == "systemd"
&& config.aos.manager.selected.package == toString pkgs.systemd
