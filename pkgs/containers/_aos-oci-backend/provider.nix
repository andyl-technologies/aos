##! Publishes the exact selected OCI backend package identity.
{lib, ...}: let
  alias = "artifact-backend";
  artifact = lib.abilities.packageOutput {};
  provide = context: {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs
      (_: request:
        if request.parameters
        then {artifact-reference = artifact;}
        else throw "the OCI artifact backend accepts only an enabled selection request")
      context.requests;
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
