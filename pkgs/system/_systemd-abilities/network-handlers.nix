##! Selects systemd's native networking renderer and lifecycle handler.
{
  config,
  lib,
  package,
  ...
}: let
  program =
    package
    // {
      mainProgram = "aos-network-handler";
      meta.mainProgram = "aos-network-handler";
    };
  identity = config.aos.abilities.identity.operations;
  accounts = {
    systemd-network = 192;
    systemd-resolve = 193;
  };
  prerequisites = lib.mapAttrsToList (name: _: identity.principal.effects.${name}.outputs.name) accounts;
in {
  aos.abilities.network.operations = {
    configure = {
      input.options.accounts = lib.mkOption {
        type = lib.types.listOf (lib.types.deferred lib.types.str);
        default = prerequisites;
        description = "Native account identities required by upstream network manager units.";
      };
      handler = {inherit program;};
    };
    ready = {
      input.options.prepared = lib.mkOption {
        type = lib.types.listOf (lib.types.deferred lib.types.str);
        default =
          lib.mapAttrsToList (_: effect: effect.outputs.resource)
          (lib.filterAttrs (_: effect: effect.enable) config.aos.abilities.network.operations.configure.effects);
        description = "Configured network resources required before observing readiness.";
      };
      handler = {inherit program;};
    };
    bootstrap.handler = {inherit program;};
  };
  aos.abilities.identity.operations = {
    group.effects =
      lib.mapAttrs (name: id: {
        input = {
          inherit name;
          requested_id = id;
        };
      })
      accounts;
    principal.effects =
      lib.mapAttrs (name: id: {
        input = {
          inherit name;
          requested_id = id;
          primary_group = identity.group.effects.${name}.outputs.name;
          home_directory = "/";
          description = "Systemd network manager";
        };
      })
      accounts;
  };
}
