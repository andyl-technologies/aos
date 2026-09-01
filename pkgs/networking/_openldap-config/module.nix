##! Typed runtime configuration for the package-owned OpenLDAP server.
{
  config,
  lib,
  ...
}: let
  cfg = config.openldap;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.nullOr (types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
      default = null;
      description = "Opaque AOS credential reference.";
    };
  });
  credentialPath = name: "/run/credentials/openldap.service/${name}";
  rendered = ''
    include /etc/openldap/schema/core.schema
    include /etc/openldap/schema/cosine.schema
    include /etc/openldap/schema/inetorgperson.schema
    pidfile /run/aos-pkg-openldap/slapd.pid
    argsfile /run/aos-pkg-openldap/slapd.args
    modulepath /libexec/openldap
    database mdb
    maxsize ${toString cfg.database.maxBytes}
    suffix "${cfg.suffix}"
    rootdn "${cfg.rootDn}"
    directory /var/lib/aos-pkg-openldap/data
    index objectClass eq
    ${lib.optionalString cfg.tls.enable "TLSCertificateFile ${credentialPath "tls-certificate"}"}
    ${lib.optionalString cfg.tls.enable "TLSCertificateKeyFile ${credentialPath "tls-private-key"}"}
    ${lib.optionalString cfg.tls.enable "TLSCACertificateFile ${credentialPath "tls-ca"}"}
    ${lib.optionalString cfg.tls.enable "TLSVerifyClient ${cfg.tls.verifyClient}"}
  '';
in {
  options.openldap = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned OpenLDAP server.";
    };
    listenUrls = mkOption {
      type = types.nonEmptyListOf (types.strMatching "(ldap|ldaps|ldapi)://[^[:space:]]*");
      default = ["ldap://127.0.0.1:389/"];
    };
    suffix = mkOption {
      type = types.strMatching "[A-Za-z][^[:cntrl:]]*";
      default = "dc=example,dc=org";
    };
    rootDn = mkOption {
      type = types.strMatching "[A-Za-z][^[:cntrl:]]*";
      default = "cn=admin,dc=example,dc=org";
    };
    rootPassword = mkOption {
      type = secretRef;
      default = {};
      description = "Opaque reference to the directory administrator password.";
    };
    database.maxBytes = mkOption {
      type = positiveInt;
      default = 1073741824;
    };
    tls = {
      enable = mkOption {
        type = types.bool;
        default = false;
      };
      certificate = mkOption {
        type = secretRef;
        default = {};
      };
      privateKey = mkOption {
        type = secretRef;
        default = {};
      };
      trustedCa = mkOption {
        type = secretRef;
        default = {};
      };
      verifyClient = mkOption {
        type = types.enum ["never" "allow" "try" "demand"];
        default = "demand";
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.rootPassword.ref != null;
        message = "openldap.enable requires openldap.rootPassword.ref";
      }
      {
        assertion = !cfg.tls.enable || builtins.all (value: value != null) [cfg.tls.certificate.ref cfg.tls.privateKey.ref cfg.tls.trustedCa.ref];
        message = "OpenLDAP TLS requires certificate, private-key, and trusted-CA references";
      }
      {
        assertion = cfg.tls.enable || builtins.all (url: !(lib.hasPrefix "ldaps://" url)) cfg.listenUrls;
        message = "ldaps listen URLs require openldap.tls.enable";
      }
    ];
    openldap.config.runtime = {
      OPENLDAP_ENABLED = cfg.enable;
      OPENLDAP_LISTEN_URLS = lib.concatStringsSep " " cfg.listenUrls;
      OPENLDAP_CONFIG_GENERATION = builtins.hashString "sha256" rendered;
    };
    openldap.credentials =
      {
        "root-password".ref = cfg.rootPassword.ref;
      }
      // lib.optionalAttrs cfg.tls.enable {
        "tls-certificate".ref = cfg.tls.certificate.ref;
        "tls-private-key".ref = cfg.tls.privateKey.ref;
        "tls-ca".ref = cfg.tls.trustedCa.ref;
      };
    environment.etc."aos/packages/openldap/slapd.conf" = {
      text = rendered;
      mode = "0444";
    };
    aos.users.users.openldap = {
      uid = 805;
      group = "openldap";
      home = "/var/lib/aos-pkg-openldap";
      shell = "/sbin/nologin";
      description = "OpenLDAP directory service";
      extraGroups = [];
    };
    aos.users.groups.openldap = {
      gid = 805;
      members = [];
    };
  };
}
