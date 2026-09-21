##! Publishes collision-checked service listener claim resources.
{lib, ...}: let
  listener = lib.abilities.interfaces.serviceListener.interface;
  inherit (listener) alias identity;
  provide = context: let
    bindingFor = requestName:
      builtins.head (
        builtins.filter
        (binding: binding.request == requestName)
        (builtins.attrValues context.bindings)
      );
  in {
    requests = {};
    resourceFragments = {};
    outputs =
      builtins.mapAttrs (requestName: _: let
        binding = bindingFor requestName;
      in {
        resource = {
          _type = "aos-resource-reference";
          interface = identity;
          resource = {
            provider = context.provider;
            key = binding.slot;
          };
          operations = ["observe"];
          lifetime = "instance";
        };
      })
      context.requests;
  };
in {
  config.aos.abilities.implementations.${alias} = {inherit provide;};
}
