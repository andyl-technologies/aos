##! Declares the selected manager's fixed early networking identities once.
{
  lib,
  identity,
}: let
  accounts = {
    systemd-network = {
      id = 192;
      description = "systemd Network Management";
    };
    systemd-resolve = {
      id = 193;
      description = "systemd Resolver";
    };
  };
in {
  references = lib.mapAttrsToList (name: _: identity.principal.effects.${name}.outputs.name) accounts;
  groupReferences = lib.mapAttrsToList (name: _: identity.group.effects.${name}.outputs.name) accounts;
  groups =
    lib.mapAttrs (name: policy: {
      input = {
        inherit name;
        requested_id = policy.id;
      };
    })
    accounts;
  principals =
    lib.mapAttrs (name: policy: {
      input = {
        inherit name;
        requested_id = policy.id;
        primary_group = identity.group.effects.${name}.outputs.name;
        home_directory = "/";
        description = policy.description;
      };
    })
    accounts;
}
