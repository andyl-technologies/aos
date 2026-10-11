##! Reuses the retained PostgreSQL topology and credential regression fixture.
{
  lib,
  self,
}: {
  topologyAndCredentials = import ../../../tests/abilities/postgresql-service.nix {
    inherit lib;
    pkgs.postgresql = self;
  };
}
