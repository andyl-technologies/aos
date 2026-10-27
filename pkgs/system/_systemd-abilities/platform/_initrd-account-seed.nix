##! Projects identities consumed by native initrd network and early services.
{
  config,
  lib,
  shells,
}: let
  networks =
    lib.filterAttrs (_: effect: effect.enable)
    config.aos.abilities.network.operations.configure.effects;
  services =
    lib.filterAttrs (_: service: service.enable && service.bootstrap)
    config.aos.services;
in
  import ./_identity-bootstrap.nix {
    inherit lib shells;
    identities = config.aos.abilities.identity.operations;
    accounts = config.aos.users;
    # Native activation reconciles these accounts after the immutable /etc
    # image is mounted. Early services need their rows before that boundary.
    principalReferences = lib.unique (
      builtins.concatMap (effect: effect.input.accounts) (builtins.attrValues networks)
      ++ builtins.concatMap (service: service.bootstrapPrincipals) (builtins.attrValues services)
    );
  }
