##! Publishes the selected systemd platform's immutable package-store locator.
{
  config,
  lib,
  ...
}: let
  readView = lib.abilities.interfaces.packageStoreReadView.interfaces.readView;
  locator = {
    schema = "aos.package-store.read-view-locator/v1";
    identity_root = "/nix/store";
    read_root = "/nix.lower/store";
    static_contract = "${config.system.build.staticAbilityContract}/contract.json";
  };
  bindingFor = bindings: requestName: let
    matches =
      builtins.filter
      (binding: binding.request == requestName)
      (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a package-store read-view request must have exactly one selected binding";
  provide = {
    instance,
    requests,
    bindings,
    ...
  }: {
    requests = {};
    resourceFragments = {};
    outputs = builtins.mapAttrs (requestName: request: let
      binding = bindingFor bindings requestName;
      resource = {
        interface = readView.identity;
        resource = {
          provider = instance.id;
          key = binding.slot;
        };
        operations = ["observe"];
        lifetime = "persistent";
      };
    in
      if request.parameters.scope == "boot-image"
      then {
        inherit locator;
        inherit resource;
      }
      else throw "the systemd package-store provider accepts only boot-image scope")
    requests;
  };
in {
  config.aos.abilities.implementations.package-store-read-view = {inherit provide;};
}
