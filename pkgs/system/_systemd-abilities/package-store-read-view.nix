##! systemd boot platform implementation of the package-store read view.
{
  abilitySelection ? null,
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
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "provider/systemd-package-store-read-view.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };

    instances = lib.mkIf (
      config.aos.abilities.environment != null
      && abilitySelection != null
      && abilitySelection.isImplementationSelected "package-store-read-view"
    ) {
      package-store-read-view.implementation = "package-store-read-view";
    };
  };
}
