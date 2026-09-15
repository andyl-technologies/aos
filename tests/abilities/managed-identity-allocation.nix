##! Checks managed service identities in one package-module fixed point.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  environmentId = lib.abilities.environmentId {
    authority = "deployment";
    key = "managed-identity-test";
    stage = "host";
  };
  credentialProvider = lib.abilities.instanceId {
    environment = environmentId;
    key = "credential-provider";
  };
  credential = key:
    lib.abilities.resourceReference {
      interface = serviceManagement.interfaces.credentialDelivery.identity;
      resource = {
        provider = credentialProvider;
        inherit key;
      };
      operations = ["observe"];
      lifetime = "persistent";
    };
  program = name: {
    artifact = lib.abilities.packageOutput {};
    entry_point = "bin/${name}";
    arguments = [];
  };

  fixedPoint = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/default.nix
      {
        options.assertions = lib.mkOption {
          type = lib.types.listOf lib.types.attrs;
          default = [];
          contributable = true;
        };
        aos.abilities.environment = builtins.removeAttrs environmentId ["_type"];
        aos.services.releaseCoordinator = {
          enable = true;
          releaseProgram = program "release";
          timestampProgram = program "timestamp";
          backupProgram = program "backup";
          restoreCheckProgram = program "restore-check";
          alertProgram = program "alert";
        };
        aos.services.chrony.enable = true;
        aos.registry-hub = {
          enable = true;
          credentials = {
            domainProbeSignerManifest = "hub-domain-probe-signer";
            routeReservationKeys = "hub-route-reservation-keys";
          };
        };
        garage = {
          enable = true;
          rpc.secret.resource = credential "garage-rpc-secret";
        };
        krb5Kdc = {
          enable = true;
          realm = "EXAMPLE.TEST";
          kdcServers = ["kdc.example.test"];
          adminServer = "kdc.example.test";
          masterPassword.name = "krb5-master";
        };
        mariadb.enable = true;
        openldap = {
          enable = true;
          rootPassword.resource = credential "openldap-root-password";
        };
      }
    ];
    packageModules = [
      {
        name = "aos";
        module.imports = [../../pkgs/tools/aos/_abilities/module.nix];
      }
      {
        name = "chrony";
        module.imports = [../../pkgs/networking/_chrony-abilities/module.nix];
      }
      {
        name = "openldap";
        module.imports = [../../pkgs/networking/_openldap/module.nix];
      }
      {
        name = "aos-hub";
        module.imports = [../../pkgs/tools/aos-hub/_aos-hub/module.nix];
      }
      {
        name = "mariadb";
        module.imports = [../../pkgs/storage/_mariadb/module.nix];
      }
      {
        name = "garage";
        module.imports = [../../pkgs/storage/_garage-config/module.nix];
      }
      {
        name = "krb5";
        module.imports = [../../pkgs/security/_krb5-kdc/module.nix];
      }
    ];
  };
  requests = fixedPoint.config.aos.abilities.requests;
  identityRequestNames = [
    "aos-hub:service-group"
    "aos-hub:service-principal"
    "aos:aos-release-backup-group"
    "aos:aos-release-backup-principal"
    "aos:aos-release-group"
    "aos:aos-release-monitor-group"
    "aos:aos-release-monitor-principal"
    "aos:aos-release-principal"
    "aos:aos-release-timestamp-group"
    "aos:aos-release-timestamp-principal"
    "chrony:chrony-group"
    "chrony:chrony-principal"
    "garage:service-group"
    "garage:service-principal"
    "krb5:service-group"
    "krb5:service-principal"
    "mariadb:service-group"
    "mariadb:service-principal"
    "openldap:service-group"
    "openldap:service-principal"
  ];
  identityRequests = builtins.map (name: requests.${name}) identityRequestNames;
  logicalIdentities =
    builtins.map
    (request:
      builtins.toJSON {
        inherit (request) consumer scope;
      })
    identityRequests;
  identityNames = builtins.sort builtins.lessThan (builtins.map (request: request.parameters.name) identityRequests);
in
  assert builtins.all (name: builtins.hasAttr name requests) identityRequestNames;
  assert builtins.all (assertion: assertion.assertion) fixedPoint.config.assertions;
  assert builtins.all (request: request.parameters.allocation == "managed") identityRequests;
  assert builtins.all (request: !(request.parameters ? requested_id)) identityRequests;
  assert identityNames
  == [
    "aos-hub"
    "aos-hub"
    "aos-release"
    "aos-release"
    "aos-release-backup"
    "aos-release-backup"
    "aos-release-monitor"
    "aos-release-monitor"
    "aos-release-timestamp"
    "aos-release-timestamp"
    "chrony"
    "chrony"
    "garage"
    "garage"
    "krb5-kdc"
    "krb5-kdc"
    "mariadb"
    "mariadb"
    "openldap"
    "openldap"
  ];
  assert builtins.length (lib.unique logicalIdentities) == builtins.length logicalIdentities; true
