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
}: let
  # Externally finalized systems publish no raw image; the media evaluation's
  # assertions then explain why media cannot be built.
  releaseImage =
    if system.config.aos.boot.secureBoot.externalFinalization.enable
    then null
    else system.config.system.build.image.raw;

  media =
    (system.extendModules {
      modules = [
        {
          aos.image.installer = {
            media = true;
            inherit releaseImage hostConfiguration;
          };
        }
      ];
    })
    .config;

  # Media is not reached through system.build.toplevel, which is where
  # assertions are normally enforced. Without this check an unsupported
  # system yields a null result instead of the reason it is unsupported.
  failedAssertions = builtins.filter (assertion: !assertion.assertion) media.assertions;
in
  if failedAssertions == []
  then media.system.build.installerMedia
  else
    throw ''
      Failed assertions:
      ${builtins.concatStringsSep "\n" (builtins.map (assertion: "  - ${assertion.message}") failedAssertions)}
    ''
