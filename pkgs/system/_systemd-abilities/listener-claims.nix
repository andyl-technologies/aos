##! Systemd implementation of provider-neutral service listener claims.
{
  config,
  lib,
  ...
}: let
  listener = lib.abilities.interfaces.serviceListener.interface;
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  config.aos.abilities = {
    implementations.${listener.alias} = {
      description = "Reserves exclusive host listener slots for services managed by systemd.";
      interface = listener.identity;
      artifact = lib.abilities.packageOutput {};
      inherit (listener) methods;
      guarantees = [];
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "listener-claims-provider.nix";
      };
      desiredType = null;
      requiredFeatures = [];
    };
    instances = lib.mkIf hostStage {
      listener-claims.implementation = listener.alias;
    };
  };
}
