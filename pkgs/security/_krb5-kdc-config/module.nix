##! Typed runtime configuration for the package-owned MIT Kerberos KDC.
{
  config,
  lib,
  ...
}: let
  cfg = config.krb5Kdc;
  inherit (lib) mkOption types;
  realmName = types.strMatching "[A-Z0-9][A-Z0-9.-]*";
  hostName = types.strMatching "[A-Za-z0-9][A-Za-z0-9.-]*";
  duration = types.strMatching "[1-9][0-9]*[smhd]";
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.nullOr (types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
      default = null;
      description = "Opaque reference to the KDC database master password.";
    };
  });
  krb5Conf = ''
    [libdefaults]
      default_realm = ${cfg.realm}
      dns_lookup_kdc = false
      dns_lookup_realm = false
      rdns = false

    [realms]
      ${cfg.realm} = {
        ${lib.concatMapStringsSep "\n    " (server: "kdc = ${server}") cfg.kdcServers}
        admin_server = ${cfg.adminServer}
      }

    [domain_realm]
      .${lib.toLower cfg.realm} = ${cfg.realm}
      ${lib.toLower cfg.realm} = ${cfg.realm}
  '';
  kdcConf = ''
    [kdcdefaults]
      kdc_ports = 88
      kdc_tcp_ports = 88

    [realms]
      ${cfg.realm} = {
        database_name = /var/lib/aos-pkg-krb5-kdc/principal
        key_stash_file = /var/lib/aos-pkg-krb5-kdc/.k5.${cfg.realm}
        acl_file = /etc/aos/packages/krb5-kdc/kadm5.acl
        max_life = ${cfg.maxLife}
        max_renewable_life = ${cfg.maxRenewableLife}
      }

    [logging]
      kdc = FILE:/var/log/krb5-kdc/kdc.log
      admin_server = FILE:/var/log/krb5-kdc/kadmind.log
  '';
in {
  options.krb5Kdc = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned Kerberos KDC.";
    };
    enableAdminServer = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the kadmind remote administration service.";
    };
    realm = mkOption {
      type = realmName;
      default = "LOCALDOMAIN";
      description = "Kerberos realm served by this KDC.";
    };
    kdcServers = mkOption {
      type = types.listOf hostName;
      default = ["localhost"];
      description = "Ordered KDC host names published to clients.";
    };
    adminServer = mkOption {
      type = hostName;
      default = "localhost";
      description = "Host name of the Kerberos administration server.";
    };
    maxLife = mkOption {
      type = duration;
      default = "10h";
      description = "Maximum ticket lifetime.";
    };
    maxRenewableLife = mkOption {
      type = duration;
      default = "7d";
      description = "Maximum renewable ticket lifetime.";
    };
    acl = mkOption {
      type = types.listOf (types.strMatching "[^\n\r]+");
      default = ["*/admin@${cfg.realm} *"];
      description = "kadmind ACL entries.";
    };
    masterPassword = mkOption {
      type = secretRef;
      default = {};
      description = "Opaque initial KDC database master password.";
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.kdcServers != [];
        message = "krb5Kdc.enable requires at least one krb5Kdc.kdcServers entry";
      }
      {
        assertion = !cfg.enable || cfg.masterPassword.ref != null;
        message = "krb5Kdc.enable requires krb5Kdc.masterPassword.ref";
      }
      {
        assertion = !cfg.enableAdminServer || cfg.enable;
        message = "krb5Kdc.enableAdminServer requires krb5Kdc.enable";
      }
    ];
    "krb5-kdc".config.runtime = {
      KRB5_KDC_ENABLED = cfg.enable;
      KRB5_KADMIND_ENABLED = cfg.enable && cfg.enableAdminServer;
      KRB5_REALM = cfg.realm;
    };
    "krb5-kdc".credentials = lib.optionalAttrs (cfg.masterPassword.ref != null) {
      master-password.ref = cfg.masterPassword.ref;
    };
    environment.etc = {
      "aos/packages/krb5-kdc/krb5.conf" = {
        text = krb5Conf;
        mode = "0444";
      };
      "aos/packages/krb5-kdc/kdc.conf" = {
        text = kdcConf;
        mode = "0444";
      };
      "aos/packages/krb5-kdc/kadm5.acl" = {
        text = lib.concatStringsSep "\n" cfg.acl + "\n";
        mode = "0444";
      };
    };
    users.groups.krb5-kdc.gid = 806;
    users.users.krb5-kdc = {
      uid = 806;
      gid = 806;
      home = "/var/lib/aos-pkg-krb5-kdc";
      shell = "/sbin/nologin";
    };
  };
}
