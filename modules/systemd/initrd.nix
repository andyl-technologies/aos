##! Adds authenticated RFC executable-carrier inputs to the selected initrd provider.
##!
##! The selected manager owns initrd units and materialization. Carrier images
##! also reserve the mapper major used by the static first-launcher path.
{
  config,
  lib,
  ...
}: let
  carrierSelected = config.boot.initrd.systemd.mountExecutableCarrier != null;
  mapperMajorParameter = "dm_mod.major=252";
  # Kernel parameter names treat hyphens and underscores as equivalent.
  mapperMajorParameters =
    builtins.filter
    (parameter: lib.hasPrefix "dm_mod.major=" (lib.replaceStrings ["-"] ["_"] parameter))
    config.aos.boot.kernelParams;
in {
  options.boot.initrd.systemd = {
    mountExecutableCarrier = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = ''
        Optional immutable Mount executable carrier artifact. Its output must
        contain carrier.ext4, carrier.hash, and carrier.root-hash. The initrd
        builder verifies the dm-verity tree and embeds all three beneath the
        signed stage-1 EROFS image. The signed kernel command line reserves
        device-mapper major 252. Staging does not activate the carrier or
        authorize Mount startup capture.
      '';
    };
  };

  config = lib.mkIf carrierSelected {
    # AOSMMSTA1 records raw st_dev. A fixed minor alone cannot make that
    # identity stable when the kernel allocates the mapper major at boot.
    aos.boot.kernelParams = [mapperMajorParameter];
    assertions = [
      {
        assertion =
          mapperMajorParameters
          != []
          && builtins.all (parameter: parameter == mapperMajorParameter) mapperMajorParameters;
        message = "The signed Mount executable carrier reserves device-mapper major 252; conflicting dm_mod.major parameters are invalid.";
      }
    ];
  };
}
