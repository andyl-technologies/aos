##! Publishes the exact selected OCI backend package identity.
{
  artifactLocatorFor,
  lib,
  ...
}: let
  alias = "artifact-backend";
  artifact = lib.abilities.packageOutput {};
  artifactReference =
    {_type = "aos-artifact-reference";}
    // (artifactLocatorFor artifact).artifactReference;
  provide = context: {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs
      (_: request:
        if request.parameters
        then {artifact-reference = artifactReference;}
        else throw "the OCI artifact backend accepts only an enabled selection request")
      context.requests;
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
