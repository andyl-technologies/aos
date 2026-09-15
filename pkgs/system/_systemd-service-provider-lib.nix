##! Pure systemd service realization helpers.
{lib}: let
  hash = value: builtins.hashString "sha256" (builtins.toJSON value);

  normalizedResourceId = resource: {
    provider = {
      environment = {
        inherit (resource.provider.environment) authority key stage;
      };
      inherit (resource.provider) key;
    };
    inherit (resource) key;
  };

  checkedLocalKey = context: value:
    if lib.abilities.types.localKey.check value
    then value
    else throw "${context} must be an AOS local key";

  unitNameForResource = resource: let
    normalized = normalizedResourceId resource;
    readableKey = checkedLocalKey "systemd service resource key" normalized.key;
  in "aos-${readableKey}-${hash normalized}.service";

  socketUnitNameForResource = resource: socketKey: let
    normalized = normalizedResourceId resource;
    readableKey = checkedLocalKey "systemd socket key" socketKey;
    identity = {
      resource = normalized;
      socket = readableKey;
    };
  in "aos-${readableKey}-${hash identity}.socket";
in {
  inherit normalizedResourceId socketUnitNameForResource unitNameForResource;
}
