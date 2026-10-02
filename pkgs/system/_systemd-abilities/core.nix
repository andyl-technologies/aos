##! Publishes exact systemd platform tools to native boot consumers.
{
  lib,
  package,
  ...
}: {
  options.aos.boot.imageEvidenceExecutable = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    description = "Retained executable that recomputes boot image measurement evidence.";
  };
  options.aos.boot.imageRolloutPlatformExecutable = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    internal = true;
    description = "Retained executable implementing authenticated boot image transitions.";
  };

  config.aos.boot.imageEvidenceExecutable = "${package}/bin/aos-systemd-image-evidence";
  config.aos.boot.imageRolloutPlatformExecutable = "${package}/bin/aos-systemd-boot-platform";
}
