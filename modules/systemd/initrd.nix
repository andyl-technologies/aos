##! Adds authenticated RFC executable-carrier inputs to the selected initrd provider.
##!
##! The selected manager owns initrd units and materialization; this option only
##! supplies the immutable carrier consumed by that same native builder.
{lib, ...}: {
  options.boot.initrd.systemd = {
    mountExecutableCarrier = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = ''
        Optional immutable Mount executable carrier artifact. Its output must
        contain carrier.ext4, carrier.hash, and carrier.root-hash. The initrd
        builder verifies the dm-verity tree and embeds all three beneath the
        signed stage-1 EROFS image. This only stages the carrier; it does not
        activate it or authorize Mount startup capture.
      '';
    };

  };
}
