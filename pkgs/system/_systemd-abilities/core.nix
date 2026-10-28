##! Publishes exact systemd platform tools to native boot consumers.
{
  lib,
  package,
  ...
}: let
  bootMeasurementsExecutable = "${package.handlers}/bin/aos-systemd-boot-measurements";
in {
  options.aos.boot.bootMeasurementsExecutable = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    description = "Retained executable that recomputes boot image measurement evidence.";
  };
  # Former name, kept so existing configurations that read it still evaluate.
  options.aos.boot.imageEvidenceExecutable = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    description = "Alias of aos.boot.bootMeasurementsExecutable.";
  };
  options.aos.boot.imageRolloutPlatformExecutable = lib.mkOption {
    type = lib.types.pathInStore;
    readOnly = true;
    internal = true;
    description = "Retained executable implementing authenticated boot image transitions.";
  };

  config.aos.boot.bootMeasurementsExecutable = bootMeasurementsExecutable;
  config.aos.boot.imageEvidenceExecutable = bootMeasurementsExecutable;
  config.aos.boot.imageRolloutPlatformExecutable = "${package.handlers}/bin/aos-systemd-boot-platform";
  config.aos.abilities.initSystem.operations.install.effects.default.input = {
    executable = "${package}/lib/systemd/systemd";
    arguments = [];
  };
  config.aos.abilities.configuration.operations.file.effects.systemd-credential-encrypt-provider.input = {
    path = "/etc/aos/providers/credential-encrypt";
    content = "${package.handlers}/bin/aos-systemd-credential-encrypt\n";
    mode = "0444";
  };
}
