##! Publishes the selected authorization-service resource.
{
  config,
  lib,
  packageName,
  ...
}: let
  alias = "authorization-service-availability";
  declaration = config.aos.abilities.interfaces."${packageName}:${alias}";
  interface = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  authorizationResources =
    builtins.filter
    (resource:
      resource.kind
      == "aos.service.instance"
      && (resource.value.manager_identity or null) != null
      && resource.value.manager_identity.name == "polkit"
      && (resource.value.readiness or null) != null)
    (builtins.attrValues config.aos.abilities.resolvedResources);
  authorizationResource =
    if builtins.length authorizationResources == 1
    then builtins.head authorizationResources
    else throw "authorization-service availability requires exactly one package-owned Polkit service resource";
  reference = {
    _type = "aos-resource-reference";
    inherit interface;
    inherit (authorizationResource) resource lifetime;
    operations = ["observe"];
  };
  provide = context: {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs
      (_: request:
        if request.parameters.scope == "system"
        then {resource = reference;}
        else throw "authorization-service availability accepts only the system scope")
      context.requests;
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
