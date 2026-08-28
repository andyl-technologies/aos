##! Positive and negative evaluation contracts for the PostgreSQL module.
{
  lib,
  pkgs,
  module,
}: let
  projection = {lib, ...}: {
    options = {
      assertions = lib.mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = [];
      };
      environment.etc = lib.mkOption {
        type = lib.types.attrs;
        default = {};
      };
      postgresql.config = lib.mkOption {
        type = lib.types.attrs;
        default = {};
      };
      postgresql.credentials = lib.mkOption {
        type = lib.types.attrs;
        default = {};
      };
    };
  };
  evaluate = configuration:
    lib.evalModules {
      modules = [
        module
        projection
        {config = configuration;}
      ];
    };
  assertionsHold = evaluated:
    builtins.all (assertion: assertion.assertion) evaluated.config.assertions;

  positive = evaluate {
    postgresql = {
      enable = true;
      clusterName = "production";
      listen = {
        addresses = ["127.0.0.1"];
        port = 55432;
      };
      bootstrap.password.ref = "system-credential:postgres-bootstrap";
      topology = "standby";
      replication = {
        primary = {
          host = "postgres-primary.internal";
          port = 5433;
        };
        passfile.ref = "desired-toml:postgres-replication";
        slot = "standby_1";
      };
      tls = {
        enable = true;
        certificate.ref = "system-credential:postgres-cert";
        privateKey.ref = "system-credential:postgres-key";
      };
      settings.log_min_duration_statement = 250;
    };
  };
  positiveConfig = positive.config.postgresql.renderedConfig;

  missingBootstrap = evaluate {
    postgresql.enable = true;
  };
  malformedHba = evaluate {
    postgresql.authentication.rules = [
      {
        type = "host";
        method = "reject";
      }
    ];
  };
  reservedOverride = evaluate {
    postgresql.settings.port = 6000;
  };
  invalidPort = builtins.tryEval (
    builtins.deepSeq
    (evaluate {postgresql.listen.port = 70000;}).config.postgresql.listen.port
    true
  );
in
  assert assertionsHold positive;
  assert lib.hasInfix "port = 55432" positiveConfig;
  assert lib.hasInfix "primary_conninfo = 'host=postgres-primary.internal port=5433" positiveConfig;
  assert lib.hasInfix "log_min_duration_statement = 250" positiveConfig;
  assert !lib.hasInfix "system-credential:postgres-bootstrap" positiveConfig;
  assert positive.config.postgresql.config.service.POSTGRESQL_PRIMARY_HOST == "postgres-primary.internal";
  assert positive.config.postgresql.config.service.POSTGRESQL_PRIMARY_PORT == 5433;
  assert positive.config.postgresql.credentials ? "bootstrap-superuser-password";
  assert positive.config.postgresql.credentials ? "replication-passfile";
  assert positive.config.postgresql.credentials ? "tls-private-key";
  assert !assertionsHold missingBootstrap;
  assert !assertionsHold malformedHba;
  assert !assertionsHold reservedOverride;
  assert !invalidPort.success;
    pkgs.runCommand "storage-postgresql-module-contract" {
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      mkdir -p "$out"
      printf '%s\n' verified > "$out/result"
    ''
