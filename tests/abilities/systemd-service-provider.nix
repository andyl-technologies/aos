##! Focused checks for systemd-owned service realization helpers.
{lib}: let
  provider = import ../../pkgs/system/_systemd-service-provider-lib.nix {inherit lib;};
  resource = {
    provider = {
      environment = {
        authority = "deployment";
        key = "production";
        stage = "host";
      };
      key = "systemd";
    };
    key = "main";
  };
  alternateResource =
    resource
    // {
      provider =
        resource.provider
        // {
          environment = resource.provider.environment // {key = "recovery";};
        };
    };
  maximumKey = builtins.concatStringsSep "" (builtins.genList (_: "a") 128);
  maximumResource = resource // {key = maximumKey;};
  maximumSocketName = provider.socketUnitNameForResource resource maximumKey;
  maximumServiceName = provider.unitNameForResource maximumResource;
  rejects = value: !(builtins.tryEval value).success;
in
  assert provider.normalizedResourceId (resource // {ignored = true;}) == resource;
  assert provider.unitNameForResource resource == "aos-main-def11be2fcaeade5486a6a7aa900a108ff3b1734b6c4ebe6a58901d03e505d98.service";
  assert provider.unitNameForResource resource != provider.unitNameForResource alternateResource;
  assert provider.socketUnitNameForResource resource "http" != provider.socketUnitNameForResource resource "https";
  assert builtins.stringLength maximumServiceName <= 255;
  assert builtins.stringLength maximumSocketName <= 255;
  assert rejects (provider.unitNameForResource (resource // {key = "";}));
  assert rejects (provider.unitNameForResource (resource // {key = "invalid/key";})); true
