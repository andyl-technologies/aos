##! Derives bootable installer media for an evaluated AOS system.
#
# The media evaluation extends the system with installer mode so its kernel
# and initrd become the installer UKI, while the original evaluation supplies
# the release image that is installed. Both evaluations share every authored
# module, so host.nix is evaluated against the same base library at install
# time and at first boot.
{
  system,
  hostConfiguration ? null,
}:
(system.extendModules {
  modules = [
    {
      aos.image.installer = {
        media = true;
        releaseImage = system.config.system.build.image.raw;
        inherit hostConfiguration;
      };
    }
  ];
})
.config
.system
.build
.installerMedia
