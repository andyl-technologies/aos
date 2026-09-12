##! Checks production structured packages retain their legacy catalog surface.
{
  lib,
  pkgs,
}: let
  packageContract = package: let
    ability = builtins.fromJSON (
      builtins.unsafeDiscardStringContext package.abilities.abilityTemplateJson
    );
    exposure = package.expose.passthru.manifest;
  in {
    inherit ability exposure;
    hasConfigModule = package ? config && package ? configModule;
  };

  nginx = packageContract pkgs.nginx;
  postgresql = packageContract pkgs.postgresql;

  retainsLegacySurface = contract:
    contract.ability.activation_mode
    == "structured-effects"
    && contract.hasConfigModule
    && contract.exposure.expose.config.artifacts != []
    && contract.exposure.expose.units != []
    && contract.exposure.permissions.network == "host"
    && contract.exposure.permissions."host-paths" != [];
in
  assert retainsLegacySurface nginx;
  assert retainsLegacySurface postgresql;
  assert nginx.exposure.permissions.capabilities == ["CAP_NET_BIND_SERVICE"];
  assert postgresql.exposure.expose.target == "aos-pkg-postgresql.target"; true
