##! Pure configured checks for the native PostgreSQL package module.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  environmentId = lib.abilities.environmentId {
    authority = "deployment";
    key = "postgresql-test";
    stage = "host";
  };
  environment = builtins.removeAttrs environmentId ["_type"];
  credentialProvider = lib.abilities.instanceId {
    environment = environmentId;
    key = "credential-provider";
  };
  credential = name:
    lib.abilities.resourceReference {
      interface = serviceManagement.interfaces.credentialDelivery.identity;
      resource = {
        provider = credentialProvider;
        key = name;
      };
      operations = ["observe"];
      lifetime = "persistent";
    };
  evaluate = postgresqlConfig:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        ../../modules/abilities/default.nix
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
            contributable = true;
          };
          aos.abilities.environment = environment;
          postgresql = postgresqlConfig;
        }
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "postgresql";
          module = pkgs.postgresql.module + "/module.nix";
        }
      ]));

    };
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
  standby = evaluate {
    enable = true;
    topology = "standby";
    replication = {
      primary = {
        host = "postgres-primary.internal";
        port = 5433;
      };
      passfile.resource = credential "replication-passfile";
      slot = "standby_1";
    };
    tls = {
      enable = true;
      certificate.resource = credential "tls-certificate";
      privateKey.resource = credential "tls-private-key";
      ca.resource = credential "tls-ca";
    };
  };
  assertionsHold = evaluated:
    builtins.all (assertion: assertion.assertion) evaluated.config.assertions;
  disabledAbilities = disabled.config.aos.abilities;
  standaloneAbilities = standalone.config.aos.abilities;
  standbyAbilities = standby.config.aos.abilities;
  standaloneRequests = builtins.attrNames standaloneAbilities.requests;
  standbyRequests = builtins.attrNames standbyAbilities.requests;
  mainStorage = standaloneAbilities.requests."postgresql:main-storage".parameters.mounts;
  serverSource = standbyAbilities.requests."postgresql:server-configuration".parameters.source;
  missingBootstrap = evaluate {enable = true;};
  missingStandby = evaluate {
    enable = true;
    topology = "standby";
  };
  invalidTls = evaluate {
    enable = true;
    bootstrap.password.resource = credential "bootstrap-password";
    tls.enable = true;
    tls.certificate.resource = credential "tls-certificate";
  };
  reservedSetting = evaluate {
    enable = true;
    bootstrap.password.resource = credential "bootstrap-password";
    settings.port = 6000;
  };
in
  assert assertionsHold standalone;
  assert assertionsHold standby;
  assert !assertionsHold missingBootstrap;
  assert !assertionsHold missingStandby;
  assert !assertionsHold invalidTls;
  assert !assertionsHold reservedSetting;
  assert disabledAbilities.instances == {};
  assert disabledAbilities.requests == {};
  assert builtins.elem "postgresql:initialize-lifecycle" standaloneRequests;
  assert builtins.elem "postgresql:main-lifecycle" standaloneRequests;
  assert builtins.elem "postgresql:credential-bootstrap-superuser-password" standaloneRequests;
  assert builtins.elem "postgresql:credential-bootstrap-superuser-password-source" standaloneRequests;
  assert !(builtins.elem "postgresql:credential-replication-passfile" standaloneRequests);
  assert builtins.elem "postgresql:credential-replication-passfile" standbyRequests;
  assert builtins.elem "postgresql:credential-tls-certificate" standbyRequests;
  assert builtins.elem "postgresql:credential-tls-private-key" standbyRequests;
  assert builtins.elem "postgresql:credential-tls-ca" standbyRequests;
  assert serverSource.kind == "interpolated-text";
  assert builtins.any (fragment: fragment.kind == "execution-path") serverSource.fragments;
  assert builtins.map (mount: mount.source.request) mainStorage
  == ["postgresql:state-storage" "postgresql:runtime-storage"];
  assert builtins.all (mount: mount.source._type == "aos-request-output-reference") mainStorage;
  assert builtins.all (mount: mount.source.output == "planned-path") mainStorage;
  assert !(lib.hasInfix "POSTGRESQL_CONFIG_GENERATION" (builtins.toJSON standaloneAbilities.requests));
  assert !(lib.hasInfix "/etc/postgresql" (builtins.toJSON standaloneAbilities.requests));
  assert !(lib.hasInfix "/run/credentials" (builtins.toJSON standbyAbilities.requests)); true
