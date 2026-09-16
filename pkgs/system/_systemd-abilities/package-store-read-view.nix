##! systemd boot platform implementation of the package-store read view.
{
  config,
  lib,
  ...
}: let
  readView = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  artifact = lib.abilities.packageOutput {};
in {
  config.aos.abilities = {
    implementations.package-store-read-view = {
      description = "Exposes the immutable package-store view assembled by the selected systemd boot platform.";
      interface = readView.identity;
      inherit artifact;
      inherit (readView) methods;
      guarantees = [];
      providerModule = {
        inherit artifact;
        path = "share/aos/providers/systemd-package-store-read-view.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };

    instances = lib.mkIf (
      config.aos.abilities.environment != null
      && config.aos.boot.systemdBoot.enable
    ) {
      package-store-read-view.implementation = "package-store-read-view";
    };
  };
}
