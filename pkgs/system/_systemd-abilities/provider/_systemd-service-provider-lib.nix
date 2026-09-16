##! Pure systemd service realization helpers.
{lib}: let
  identityKeyFor = lib.abilities.identityKeyFor;

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
    identity = identityKeyFor "aos.systemd.service-unit-key/v1" normalized;
  in "aos-${readableKey}-${identity}.service";

  unitIdentityForResource = resource: {
    kind = "unit";
    unit_name = unitNameForResource resource;
  };

  publicUnitIdentity = name: {
    kind = "unit";
    unit_name = "${checkedLocalKey "systemd public service name" name}.service";
  };

  publicTemplateUnitIdentity = name: {
    kind = "unit";
    unit_name = "${checkedLocalKey "systemd public service template name" name}@.service";
  };

  templateUnitIdentityForResource = resource: template: let
    normalized = normalizedResourceId resource;
    readableTemplate = checkedLocalKey "systemd service template key" template;
    identity = {
      resource = normalized;
      inherit template;
    };
    unitKey = identityKeyFor "aos.systemd.template-unit-key/v1" identity;
  in {
    kind = "unit";
    unit_name = "aos-${readableTemplate}-${unitKey}@.service";
  };

  templateInstanceIdentity = templateUnit: instance: {
    kind = "template-instance";
    template_unit_name = templateUnit.unit_name;
    inherit instance;
  };

  socketUnitNameForResource = resource: socketKey: managerName: let
    normalized = normalizedResourceId resource;
    readableKey = checkedLocalKey "systemd socket key" socketKey;
    identity = {
      resource = normalized;
      socket = readableKey;
    };
    unitKey = identityKeyFor "aos.systemd.socket-unit-key/v1" identity;
  in
    if managerName == null
    then "aos-${readableKey}-${unitKey}.socket"
    else "${checkedLocalKey "systemd public socket name" managerName}.socket";
in {
  inherit
    normalizedResourceId
    publicTemplateUnitIdentity
    publicUnitIdentity
    socketUnitNameForResource
    templateInstanceIdentity
    templateUnitIdentityForResource
    unitIdentityForResource
    unitNameForResource
    ;
}
