##! Publishes the exact package-owned system-bus service resource.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "system-bus-availability";
  declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
  interface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  systemBusResources =
    builtins.filter
    (resource:
      resource.kind
      == "aos.service.instance"
      && (resource.value.manager_identity or null) != null
      && resource.value.manager_identity.name == "dbus"
      && (resource.value.readiness or null) != null)
    (builtins.attrValues config.aos.abilities.resolvedResources);
  systemBus =
    if builtins.length systemBusResources == 1
    then builtins.head systemBusResources
    else throw "D-Bus availability requires exactly one package-owned system-bus service resource";
  reference = {
    _type = "aos-resource-reference";
    inherit interface;
    inherit (systemBus) resource lifetime;
    operations = ["observe"];
  };
  provide = context: {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs
      (_: request:
        if request.parameters.scope == "system-bus"
        then {readiness-resource = reference;}
        else throw "D-Bus availability accepts only the system-bus scope")
      context.requests;
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
