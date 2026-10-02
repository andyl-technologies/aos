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
  accountPolicy = import ./network-account-policy.nix {inherit lib identity;};
in {
  aos.abilities.network.operations = {
    configure = {
      input.options.accounts = lib.mkOption {
        type = lib.types.listOf (lib.types.deferred lib.types.str);
        default = accountPolicy.references;
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
    group.effects = accountPolicy.groups;
    principal.effects = accountPolicy.principals;
  };
}
