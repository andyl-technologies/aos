##! Typed runtime configuration for the package-owned rsync daemon.
{
  config,
  lib,
  ...
}: let
  cfg = config.rsyncd;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  moduleName = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.nullOr (types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
      default = null;
      description = "Opaque reference to an rsync secrets file.";
    };
  });
  moduleType = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = moduleName;
        default = name;
        readOnly = true;
      };
      comment = mkOption {
        type = types.str;
        default = "AOS rsync module ${name}";
      };
      readOnly = mkOption {
        type = types.bool;
        default = true;
      };
      authUsers = mkOption {
        type = types.listOf (types.strMatching "[A-Za-z0-9][A-Za-z0-9_.@-]*");
        default = [];
      };
      maxConnections = mkOption {
        type = positiveInt;
        default = 8;
      };
    };
  });
  bool = value:
    if value
    then "yes"
    else "no";
  renderModule = name: value: ''
    [${name}]
    path = /var/lib/aos-pkg-rsyncd/exports/${name}
    comment = ${value.comment}
    read only = ${bool value.readOnly}
    max connections = ${toString value.maxConnections}
    ${lib.optionalString (value.authUsers != []) "auth users = ${lib.concatStringsSep ", " value.authUsers}"}
    ${lib.optionalString (value.authUsers != []) "secrets file = /run/credentials/rsyncd.service/secrets-file"}
  '';
  rendered = ''
    pid file = /run/aos-pkg-rsyncd/rsyncd.pid
    lock file = /run/aos-pkg-rsyncd/rsyncd.lock
    use chroot = no
    log file = /var/log/rsyncd/rsyncd.log
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList renderModule cfg.modules)}
  '';
  authenticated = builtins.any (value: value.authUsers != []) (builtins.attrValues cfg.modules);
in {
  options.rsyncd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned rsync daemon.";
    };
    port = mkOption {
      type = types.port;
      default = 873;
      description = "TCP port on which rsyncd listens.";
    };
    address = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address on which rsyncd listens.";
    };
    modules = mkOption {
      type = types.attrsOf moduleType;
      default = {};
      description = "Exports rooted below persistent rsyncd state.";
    };
    secrets = mkOption {
      type = secretRef;
      default = {};
      description = "Opaque credential containing user:password lines.";
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.modules != {};
        message = "rsyncd.enable requires at least one rsyncd.modules entry";
      }
      {
        assertion = !authenticated || cfg.secrets.ref != null;
        message = "authenticated rsyncd modules require rsyncd.secrets.ref";
      }
    ];
    rsyncd.config.runtime = {
      RSYNCD_ENABLED = cfg.enable;
      RSYNCD_ADDRESS = cfg.address;
      RSYNCD_PORT = cfg.port;
      RSYNCD_CONFIG_GENERATION = builtins.hashString "sha256" rendered;
    };
    rsyncd.credentials = lib.optionalAttrs authenticated {"secrets-file".ref = cfg.secrets.ref;};
    environment.etc."aos/packages/rsyncd/rsyncd.conf" = {
      text = rendered;
      mode = "0444";
    };
  };
}
