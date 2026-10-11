##! Checks MariaDB service projection with optional credential-backed features.
{
  lib,
  pkgs,
}: let
  credential = name: name;
  evaluateWith = settings: extraModules:
    lib.evalPackageModules {
      scope = ["test" "mariadb"];
      packages = [pkgs.mariadb];
      operatorModules = [{aos.mariadb = settings;}] ++ extraModules;
    };
  evaluate = settings: evaluateWith settings [];
  disabled = evaluate {};
  plain = evaluate {enable = true;};
  disabledServices = evaluateWith {enable = true;} [
    ({lib, ...}: {
      aos.services."mariadb.initialize".enable = lib.mkForce false;
      aos.services."mariadb.main".enable = lib.mkForce false;
    })
  ];
  tls = evaluate {
    enable = true;
    tls = {
      enable = true;
      certificate.name = credential "certificate";
      privateKey.name = credential "private-key";
    };
    bootstrap.adminSql.name = credential "admin-sql";
  };
  files = result: result.config.aos.abilities.configuration.operations.file.effects;
in
  assert files disabled == {} && files disabledServices == {};
  assert plain.config.aos.services."mariadb.main".enable;
  assert !(files plain ? mariadb-bootstrap);
  assert files tls ? mariadb-bootstrap;
  assert (files tls).mariadb-bootstrap.input.mode == "0600";
  assert builtins.length tls.config.aos.services."mariadb.main".credentials.views == 2;
  assert tls.config.aos.abilities.credential.operations.deliver.effects.mariadb-admin-bootstrap-sql.input.name == "admin-sql"; true
