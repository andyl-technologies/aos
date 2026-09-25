##! Concrete immutable image builder selection for current system variants.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages = [pkgs.systemd];

  aos.abilities.bindings."image-builder:systemd" =
    lib.mkIf (
      config.aos.abilities.environment
      != null
      && config.aos.abilities.environment.stage == "host"
      && lib.attrByPath ["aos" "config" "evaluationMode"] "image-build" config == "image-build"
    ) {
      request = "aos:image-builder";
      implementation = "systemd:image-builder";
      providerInstance = "systemd:image-builder-provider";
      slot = "image-builder";
    };
}
