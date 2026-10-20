##! Pure configured checks for the native PostgreSQL package module.
{
  lib,
  pkgs,
}: let
  credential = name: name;
  evaluateWith = settings: extraModules:
    lib.evalPackageModules {
      scope = ["test" "postgresql"];
      packages = [pkgs.postgresql];
      operatorModules = [{aos.postgresql = settings;}] ++ extraModules;
    };
  evaluate = settings: evaluateWith settings [];
  disabled = evaluate {};
  standalone = evaluate {
    enable = true;
    clusterName = "production";
    listen = {
      addresses = ["127.0.0.1"];
      port = 55432;
    };
    bootstrap.password.name = "bootstrap-password";
    settings.log_min_duration_statement = 250;
  };
  disabledServices =
    evaluateWith {
      enable = true;
      bootstrap.password.name = "bootstrap-password";
    } [
      ({lib, ...}: {
        aos.services."postgresql.initialize".enable = lib.mkForce false;
        aos.services."postgresql.main".enable = lib.mkForce false;
      })
    ];
  standby = evaluate {
    enable = true;
    topology = "standby";
    replication = {
      primary = {
        host = "postgres-primary.internal";
        port = 5433;
      };
      passfile.name = credential "replication-passfile";
      slot = "standby_1";
    };
    tls = {
      enable = true;
      certificate.name = credential "tls-certificate";
      privateKey.name = credential "tls-private-key";
      ca.name = credential "tls-ca";
    };
  };
  assertionsHold = evaluated: builtins.all (check: check.assertion) evaluated.assertions;
  operations = result: result.config.aos.abilities;
  missingBootstrap = evaluate {enable = true;};
  missingStandby = evaluate {
    enable = true;
    topology = "standby";
  };
  invalidTls = evaluate {
    enable = true;
    bootstrap.password.name = credential "bootstrap-password";
    tls.enable = true;
    tls.certificate.name = credential "tls-certificate";
  };
  reservedSetting = evaluate {
    enable = true;
    bootstrap.password.name = credential "bootstrap-password";
    settings.port = 6000;
  };
  settingAccepted = value:
    (builtins.tryEval (builtins.deepSeq
      (evaluate {settings.application_name = value;}).config.aos.postgresql.settings
      true)).success;
in
  assert settingAccepted "" && settingAccepted "application\tname";
  assert !(settingAccepted "application\nname") && !(settingAccepted "application\rname");
  assert assertionsHold standalone && assertionsHold standby;
  assert !assertionsHold missingBootstrap && !assertionsHold missingStandby && !assertionsHold invalidTls && !assertionsHold reservedSetting;
  assert (operations disabled).configuration.operations.file.effects == {};
  assert (operations disabledServices).configuration.operations.file.effects == {};
  assert standalone.config.aos.services."postgresql.initialize".enable;
  assert standalone.config.aos.services."postgresql.main".enable;
  assert builtins.length (builtins.attrNames (operations standalone).credential.operations.deliver.effects) == 1;
  assert builtins.length (builtins.attrNames (operations standby).credential.operations.deliver.effects) == 4;
  assert builtins.length standalone.config.aos.services."postgresql.main".storage.mounts == 2;
  assert builtins.any builtins.isAttrs (operations standby).configuration.operations.file.effects.postgresql-server.input.fragments;
  assert standalone.config.aos.services."postgresql.main".lifecycle.configuration_change_action == "restart"; true
