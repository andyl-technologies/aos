##! Seeds image-owned accounts required by the selected manager and early services.
{
  config,
  lib,
  pkgs,
  ...
}: let
  identity = config.aos.abilities.identity.operations;
  accountPolicy = import ../network-account-policy.nix {inherit lib identity;};
  bootstrapServices = lib.filterAttrs (_: service: service.enable && service.bootstrap) config.aos.services;
  accountSeed = import ./_identity-bootstrap.nix {
    inherit lib;
    identities = identity;
    accounts = config.aos.users;
    principalReferences = lib.unique (
      builtins.filter (reference:
        identity.principal.effects.${lib.last reference.identity}.enable)
      accountPolicy.references
      ++ builtins.concatMap (service: service.bootstrapPrincipals) (builtins.attrValues bootstrapServices)
    );
    groupReferences = builtins.filter (reference:
      identity.group.effects.${lib.last reference.identity}.enable)
    accountPolicy.groupReferences;
    shells = import ../identity-shells.nix {inherit (pkgs) bash util-linux;};
  };
in {
  # Vendor sysusers runs before native host activation. These image-owned rows
  # preserve enabled manager identities even when a network configure request
  # omits them. Native replay validates the numeric and login policy without
  # adopting ownership of the pre-existing account rows.
  environment.etc = {
    passwd.text = accountSeed.passwd;
    group.text = accountSeed.group;
    shadow.text = accountSeed.shadow;
  };
}
