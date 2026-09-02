##! Typed, package-owned Garage runtime configuration.
{
  config,
  lib,
  ...
}: let
  inherit (lib) mkIf mkMerge mkOption types;
  cfg = config.garage;

  positiveInt = types.addCheck types.int (value: value > 0);
  socketAddress = types.strMatching "[^[:space:]]+";
  nonempty = types.addCheck types.str (value: value != "");
  secretRef = types.submodule ({...}: {
    config._module.strict = true;
    options.ref = mkOption {
      type = types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?";
      description = "Opaque AOS credential reference; secret bytes never enter Nix evaluation.";
    };
  });
  optionalSecretRef = types.nullOr secretRef;
  toml = lib.formats.toml {
    inherit lib;
    pkgs = null;
  };

  renderedConfig = toml.toTOML {
    metadata_dir = "/var/lib/aos-pkg-garage/meta";
    data_dir = "/var/lib/aos-pkg-garage/data";
    db_engine = cfg.dbEngine;
    replication_factor = cfg.replicationFactor;
    rpc_bind_addr = cfg.rpc.bindAddress;
    rpc_public_addr = cfg.rpc.publicAddress;
    bootstrap_peers = cfg.rpc.bootstrapPeers;
    s3_api = {
      api_bind_addr = cfg.s3.bindAddress;
      s3_region = cfg.s3.region;
      root_domain = cfg.s3.rootDomain;
    };
    s3_web =
      if cfg.web.enable
      then {
        bind_addr = cfg.web.bindAddress;
        root_domain = cfg.web.rootDomain;
      }
      else null;
    admin =
      if cfg.admin.enable
      then {
        api_bind_addr = cfg.admin.bindAddress;
        metrics_require_token = cfg.admin.metrics.requireToken;
      }
      else null;
  };
in {
  options.garage = {
    enable = lib.mkEnableOption "the Garage object-storage service";

    dbEngine = mkOption {
      type = types.enum ["lmdb" "sqlite"];
      default = "lmdb";
      description = "Embedded metadata database engine.";
    };

    replicationFactor = mkOption {
      type = positiveInt;
      default = 1;
      description = "Number of copies Garage maintains for each object.";
    };

    rpc = {
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3901";
        description = "Socket address used for Garage cluster RPC.";
      };
      publicAddress = mkOption {
        type = types.nullOr socketAddress;
        default = null;
        description = "Externally reachable cluster RPC address advertised to peers.";
      };
      bootstrapPeers = mkOption {
        type = types.listOf nonempty;
        default = [];
        description = "Garage node-ID and RPC-address peers used for cluster discovery.";
      };
      secret = mkOption {
        type = optionalSecretRef;
        default = null;
        description = "Opaque reference for the shared 32-byte hexadecimal RPC secret.";
      };
    };

    s3 = {
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3900";
        description = "Socket address used by the S3 API.";
      };
      region = mkOption {
        type = nonempty;
        default = "garage";
        description = "S3 region returned to clients and used for request signing.";
      };
      rootDomain = mkOption {
        type = types.nullOr nonempty;
        default = null;
        description = "Optional DNS suffix for virtual-host-style S3 requests.";
      };
    };

    web = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Garage's public bucket website endpoint.";
      };
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3902";
        description = "Socket address used by the bucket website endpoint.";
      };
      rootDomain = mkOption {
        type = nonempty;
        default = ".web.garage.localhost";
        description = "DNS suffix used to select website buckets.";
      };
    };

    admin = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable Garage's authenticated administration and metrics API.";
      };
      bindAddress = mkOption {
        type = socketAddress;
        default = "127.0.0.1:3903";
        description = "Socket address used by the administration API.";
      };
      token = mkOption {
        type = optionalSecretRef;
        default = null;
        description = "Opaque reference for the administration bearer token.";
      };
      metrics = {
        requireToken = mkOption {
          type = types.bool;
          default = true;
          description = "Require a bearer token when scraping metrics.";
        };
        token = mkOption {
          type = optionalSecretRef;
          default = null;
          description = "Opaque reference for the metrics bearer token.";
        };
      };
    };
  };

  config = {
    garage.config.runtime = {
      GARAGE_ENABLED =
        if cfg.enable
        then "1"
        else "0";
      GARAGE_CONFIG_GENERATION = builtins.hashString "sha256" renderedConfig;
    };

    garage.credentials = mkMerge [
      (mkIf (cfg.rpc.secret != null) {"rpc-secret" = cfg.rpc.secret;})
      (mkIf (cfg.admin.token != null) {"admin-token" = cfg.admin.token;})
      (mkIf (cfg.admin.metrics.token != null) {"metrics-token" = cfg.admin.metrics.token;})
    ];

    environment.etc."aos/packages/garage/garage.toml" = {
      mode = "0640";
      text = renderedConfig;
    };

    aos.users.users.garage = {
      uid = 804;
      group = "garage";
      home = "/var/lib/aos-pkg-garage";
      shell = "/sbin/nologin";
      description = "Garage object-storage service";
      extraGroups = [];
    };
    aos.users.groups.garage = {
      gid = 804;
      members = [];
    };

    assertions = [
      {
        assertion = !cfg.enable || cfg.rpc.secret != null;
        message = "garage.enable requires an opaque garage.rpc.secret reference";
      }
      {
        assertion = !cfg.admin.enable || cfg.admin.token != null;
        message = "garage.admin.enable requires an opaque garage.admin.token reference";
      }
      {
        assertion = !cfg.admin.metrics.requireToken || !cfg.admin.enable || cfg.admin.metrics.token != null;
        message = "garage admin metrics token enforcement requires garage.admin.metrics.token";
      }
      {
        assertion = builtins.length cfg.rpc.bootstrapPeers == builtins.length (lib.unique cfg.rpc.bootstrapPeers);
        message = "garage.rpc.bootstrapPeers must not contain duplicates";
      }
    ];
  };
}
