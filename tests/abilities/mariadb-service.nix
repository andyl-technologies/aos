##! Checks MariaDB service projection with optional credential-backed features.
{
  lib,
  pkgs,
}: let
  evaluateBase = import ./base-module-evaluation.nix {inherit lib pkgs;};
  environment = lib.abilities.environmentId {
    authority = "test";
    key = "mariadb";
    stage = "host";
  };
  credential = key:
    lib.abilities.resourceReference {
      interface = lib.abilities.interfaces.serviceManagement.interfaces.credentialDelivery.identity;
      resource = {
        provider = lib.abilities.instanceId {
          inherit environment;
          key = "credentials";
        };
        inherit key;
      };
      operations = ["observe"];
      lifetime = "persistent";
    };
  evaluateWith = settings: extraModules:
    evaluateBase {
      name = "mariadb";
      module.mariadb = settings;
      packages = [pkgs.mariadb pkgs.systemd];
      inherit extraModules;
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
      certificate.resource = credential "certificate";
      privateKey.resource = credential "private-key";
    };
    bootstrap.adminSql.resource = credential "admin-sql";
  };
  requestsFor = evaluation:
    lib.filterAttrs (name: _: lib.hasPrefix "mariadb:" name) evaluation.config.aos.abilities.requests;
  plainRequests = requestsFor plain;
  tlsRequests = requestsFor tls;
in
  assert requestsFor disabled == {};
  assert requestsFor disabledServices == {};
  assert disabledServices.config.aos.abilities.requirementTemplates == plain.config.aos.abilities.requirementTemplates;
  assert plainRequests ? "mariadb:main-lifecycle";
  assert !(plainRequests ? "mariadb:main-credentials");
  assert !(plainRequests ? "mariadb:bootstrap-configuration");
  assert tlsRequests ? "mariadb:main-credentials";
  assert tlsRequests ? "mariadb:bootstrap-configuration";
  assert tlsRequests ? "mariadb:credential-admin-bootstrap-sql"; true
