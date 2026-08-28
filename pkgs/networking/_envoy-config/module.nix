##! Package-owned, typed Envoy service configuration interface.
{
  config,
  lib,
  ...
}: let
  types = import ./types.nix {inherit lib;};
  render = import ./render.nix {inherit lib;};
  cfg = config.envoy;
  named = attrs: builtins.map (name: attrs.${name}) (builtins.attrNames attrs);
  allChains = lib.concatLists (builtins.map (listener: named listener.filterChains) (named cfg.listeners));
  downstreamTls = builtins.filter (value: value != null) (builtins.map (chain: chain.tls) allChains);
  upstreamTls = builtins.filter (value: value != null) (builtins.map (cluster: cluster.tls) (named cfg.clusters));
  allRoutes = lib.concatLists (builtins.map (chain:
    lib.concatLists (builtins.map (host: named host.routes) (named chain.virtualHosts)))
  allChains);
  allTls = downstreamTls ++ upstreamTls;
  usedCredentials = lib.unique (lib.concatLists (builtins.map (tls:
    builtins.filter (value: value != null) [
      tls.certificateCredential
      tls.privateKeyCredential
      tls.validationCaCredential
    ])
  allTls));
  certificateSourceValid = required: tls: let
    hasSds = tls.sdsSecret != null;
    hasCert = tls.certificateCredential != null;
    hasKey = tls.privateKeyCredential != null;
  in
    (hasCert == hasKey)
    && !(hasSds && hasCert)
    && (!required || hasSds || hasCert);
  validationSourceCount = tls:
    (
      if tls.validationCaCredential != null
      then 1
      else 0
    )
    + (
      if tls.validationSdsSecret != null
      then 1
      else 0
    );
  routeActionCount = route:
    (
      if route.cluster != null
      then 1
      else 0
    )
    + (
      if route.weightedClusters != {}
      then 1
      else 0
    )
    + (
      if route.directResponse != null
      then 1
      else 0
    )
    + (
      if route.redirect != null
      then 1
      else 0
    );
  routeMatchCount = route:
    (
      if route.match.prefix != null
      then 1
      else 0
    )
    + (
      if route.match.path != null
      then 1
      else 0
    )
    + (
      if route.match.safeRegex != null
      then 1
      else 0
    );
  listenerSockets = builtins.map (listener: "${listener.protocol}:${listener.address}:${toString listener.port}") (named cfg.listeners);
  referencedClusters =
    lib.concatLists (builtins.map (route:
      lib.optionals (route.cluster != null) [route.cluster]
      ++ builtins.attrNames route.weightedClusters)
    allRoutes)
    ++ builtins.filter (value: value != null) (builtins.map (chain: chain.tcpProxyCluster) allChains);
in {
  options.envoy = {
    enable = lib.mkEnableOption "the Envoy proxy service";

    node = lib.mkOption {
      type = lib.types.submodule {
        config._module.strict = true;
        options = {
          id = lib.mkOption {
            type = lib.types.strMatching ".+";
            default = "aos-envoy";
            description = "The xDS node identifier.";
          };
          cluster = lib.mkOption {
            type = lib.types.strMatching ".+";
            default = "aos";
            description = "The xDS node cluster identifier.";
          };
          metadata = lib.mkOption {
            type = lib.types.attrsOf (lib.types.either lib.types.bool (lib.types.either lib.types.int lib.types.str));
            default = {};
            description = "Non-secret xDS node metadata.";
          };
        };
      };
      default = {};
      description = "The Envoy node identity advertised to xDS servers.";
    };

    listeners = lib.mkOption {
      type = lib.types.attrsOf types.listener;
      default = {};
      contributable = true;
      description = "The statically configured listeners.";
    };

    clusters = lib.mkOption {
      type = lib.types.attrsOf types.cluster;
      default = {};
      contributable = true;
      description = "The statically configured upstream clusters.";
    };

    dynamicResources = lib.mkOption {
      type = lib.types.submodule {
        config._module.strict = true;
        options = {
          enableAds = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Whether to configure aggregated discovery service.";
          };
          adsCluster = lib.mkOption {
            type = lib.types.strMatching ".+";
            default = "xds-control-plane";
            description = "The static cluster serving ADS and SDS.";
          };
          listenersFromAds = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Whether listeners are obtained through LDS over ADS.";
          };
          clustersFromAds = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Whether clusters are obtained through CDS over ADS.";
          };
        };
      };
      default = {};
      description = "The xDS dynamic-resource configuration.";
    };

    runtimeLayers = lib.mkOption {
      type = lib.types.attrsOf types.runtimeLayer;
      default = {};
      contributable = true;
      description = "Static, non-secret Envoy runtime layers.";
    };

    admin = lib.mkOption {
      type = lib.types.submodule {
        config._module.strict = true;
        options = {
          enable = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Whether to expose the loopback administration API.";
          };
          address = lib.mkOption {
            type = lib.types.strMatching ".+";
            default = "127.0.0.1";
            description = "The administration API bind address.";
          };
          port = lib.mkOption {
            type = lib.types.port;
            default = 9901;
            description = "The administration API port.";
          };
          accessLogPath = lib.mkOption {
            type = lib.types.enum [
              "/dev/null"
              "/var/log/aos-pkg-envoy/admin-access.log"
            ];
            default = "/var/log/aos-pkg-envoy/admin-access.log";
            description = "The administration access-log sink; the default is the service-owned log directory.";
          };
        };
      };
      default = {};
      description = "The local Envoy administration interface.";
    };

    telemetry = lib.mkOption {
      type = lib.types.submodule {
        config._module.strict = true;
        options = {
          statsPrefix = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "An optional fixed tag attached to emitted metrics.";
          };
          statsd = lib.mkOption {
            type = lib.types.nullOr types.socketAddress;
            default = null;
            description = "An optional StatsD sink.";
          };
        };
      };
      default = {};
      description = "Envoy telemetry sinks and tags.";
    };

    renderedBootstrap = lib.mkOption {
      type = lib.types.attrs;
      internal = true;
      readOnly = true;
      description = "The rendered Envoy v3 bootstrap document.";
    };
  };

  config = {
    envoy.renderedBootstrap = render cfg;
    envoy.config.bootstrap = cfg.renderedBootstrap;
    envoy.config.service.ENVOY_ENABLED =
      if cfg.enable
      then 1
      else 0;

    assertions = [
      {
        assertion = !cfg.enable || cfg.listeners != {} || cfg.dynamicResources.listenersFromAds;
        message = "envoy.enable requires at least one static listener or listenersFromAds";
      }
      {
        assertion = builtins.length listenerSockets == builtins.length (lib.unique listenerSockets);
        message = "envoy.listeners must not bind duplicate protocol/address/port tuples";
      }
      {
        assertion = builtins.all (chain: (chain.virtualHosts != {}) != (chain.tcpProxyCluster != null)) allChains;
        message = "each Envoy filter chain must configure exactly one of virtualHosts or tcpProxyCluster";
      }
      {
        assertion = builtins.all (route: routeActionCount route == 1) allRoutes;
        message = "each Envoy route must configure exactly one action";
      }
      {
        assertion = builtins.all (route: routeMatchCount route == 1) allRoutes;
        message = "each Envoy route must configure exactly one of prefix, path, or safeRegex";
      }
      {
        assertion =
          builtins.all (certificateSourceValid true) downstreamTls
          && builtins.all (certificateSourceValid false) upstreamTls;
        message = "Envoy TLS certificate sources must be one SDS secret or a complete certificate/private-key credential pair";
      }
      {
        assertion = builtins.all (name: cfg.credentials ? ${name}) usedCredentials;
        message = "each Envoy TLS credential handle must have an envoy.credentials reference";
      }
      {
        assertion = builtins.all (tls: !tls.requireClientCertificate || validationSourceCount tls == 1) downstreamTls;
        message = "Envoy downstream client-certificate verification requires exactly one CA credential or SDS validation context";
      }
      {
        assertion = builtins.all (tls: validationSourceCount tls == 1) upstreamTls;
        message = "Envoy upstream TLS requires exactly one CA credential or SDS validation context";
      }
      {
        assertion = !builtins.any (tls: tls.sdsSecret != null || tls.validationSdsSecret != null) allTls || cfg.dynamicResources.enableAds;
        message = "Envoy SDS secret references require dynamicResources.enableAds";
      }
      {
        assertion = builtins.all (name: cfg.clusters ? ${name} || cfg.dynamicResources.clustersFromAds) referencedClusters;
        message = "Envoy routes and TCP proxies may reference only configured clusters unless CDS is enabled";
      }
      {
        assertion = !cfg.dynamicResources.listenersFromAds && !cfg.dynamicResources.clustersFromAds || cfg.dynamicResources.enableAds;
        message = "Envoy LDS/CDS over ADS requires dynamicResources.enableAds";
      }
      {
        assertion = !cfg.dynamicResources.enableAds || cfg.clusters ? ${cfg.dynamicResources.adsCluster};
        message = "Envoy ADS requires a static cluster named by dynamicResources.adsCluster";
      }
      {
        assertion = !cfg.admin.enable || cfg.admin.address == "127.0.0.1" || cfg.admin.address == "::1";
        message = "Envoy admin is restricted to a loopback address";
      }
    ];
  };
}
