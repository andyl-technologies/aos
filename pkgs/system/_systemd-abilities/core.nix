##! Publishes exact systemd platform tools to native boot consumers.
{
  config,
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

  config.aos.boot.imageEvidenceExecutable = "${package.handlers}/bin/aos-systemd-image-evidence";
  config.aos.boot.imageRolloutPlatformExecutable = "${package.handlers}/bin/aos-systemd-boot-platform";
  config.aos.abilities.initSystem.operations.install.effects.default.input = {
    executable = "${package}/lib/systemd/systemd";
    arguments = [];
  };
  # This locator serves the host's `apm credential encrypt` authoring command.
  # Initrd credential recovery uses PID 1 directly and needs no authoring file.
  config.aos.abilities.configuration.operations.file.effects.systemd-credential-encrypt-provider = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    input = {
      path = "/etc/aos/providers/credential-encrypt";
      content = "${package.handlers}/bin/aos-systemd-credential-encrypt\n";
      mode = "0444";
    };
  };
}
