##! Package-owned, typed Envoy service configuration interface.
{
  config,
  lib,
  package,
  ...
}: let
  envoyTypes = import ./types.nix {inherit lib;};
  render = import ./render.nix {inherit lib;};
  types = lib.types;
  operations = config.aos.abilities;
  credentialConfigured = value: (value.name != null) != (value.resource != null);
  credentialNames = [
    "tls-certificate"
    "tls-private-key"
    "validation-ca"
  ];
  credentialReference = types.submodule operations.credential.operations.deliver.input;
  credentialReferences = types.attrsOf credentialReference;
  nodeType = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      id = {
        type = envoyTypes.nonEmpty;
        default = "aos-envoy";
        description = "The xDS node identifier.";
      };
      cluster = {
        type = envoyTypes.nonEmpty;
        default = "aos";
        description = "The xDS node cluster identifier.";
      };
      metadata = {
        type = envoyTypes.metadata;
        default = {};
        description = "Non-secret xDS node metadata.";
      };
    };
  };
  dynamicResourcesType = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      enableAds = {
        type = types.bool;
        default = false;
        description = "Whether to configure aggregated discovery service.";
      };
      adsCluster = {
        type = envoyTypes.nonEmpty;
        default = "xds-control-plane";
        description = "The static cluster serving ADS and SDS.";
      };
      listenersFromAds = {
        type = types.bool;
        default = false;
        description = "Whether listeners are obtained through LDS over ADS.";
      };
      clustersFromAds = {
        type = types.bool;
        default = false;
        description = "Whether clusters are obtained through CDS over ADS.";
      };
    };
  };
  adminType = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      enable = {
        type = types.bool;
        default = true;
        description = "Whether to expose the loopback administration API.";
      };
      address = {
        type = envoyTypes.nonEmpty;
        default = "127.0.0.1";
        description = "The administration API bind address.";
      };
      port = {
        type = envoyTypes.port;
        default = 9901;
        description = "The administration API port.";
      };
      accessLog = {
        type = types.enum ["disabled" "service-log"];
        default = "service-log";
        description = "Whether administration requests are discarded or written to the service-owned log storage.";
      };
    };
  };
  telemetryType = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      statsPrefix = {
        type = types.str;
        default = "";
        description = "An optional fixed tag attached to emitted metrics.";
      };
      statsd = {
        type = types.nullOr envoyTypes.socketAddress;
        default = null;
        description = "An optional StatsD sink.";
      };
    };
  };
  cfg = envoyTypes.normalize config.aos.envoy;
  serviceEnabled = config.aos.services."envoy.main".enable;
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
  configuredCredentials =
    builtins.filter
    (name:
      cfg.credentials ? ${name})
    usedCredentials;
  command = arguments: {
    executable = {
      path = "${package}/bin/envoy";
      inherit arguments;
    };
    ignore_failure = false;
  };
  credentialPaths = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = operations.credential.operations.deliver.effects."envoy-${name}".outputs.path;
    })
    configuredCredentials);
  adminLogEnabled = cfg.admin.enable && cfg.admin.accessLog == "service-log";
  adminLogPath =
    if adminLogEnabled
    then operations.filesystem.operations.view.effects.envoy-admin-log.outputs.path
    else null;
  renderedBootstrap =
    render {
      inherit adminLogPath credentialPaths;
    }
    cfg;
  service = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = ["bind-privileged-network-port"];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "shared";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      security_label = "aos-pkg-envoy";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "restricted";
      isolated_identity_mapping = "none";
    };
    service = "envoy";
    lifecycle = {
      description = "Envoy proxy";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [(command ["--mode" "validate" "--config-path" (operations.configuration.operations.file.effects.envoy.outputs.path)])];
      start = [(command ["--disable-hot-restart" "--config-path" (operations.configuration.operations.file.effects.envoy.outputs.path)])];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 2000;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 60000;
    };
    dependencies = {
      after = [(operations.network.operations.ready.effects.envoy.outputs.resource)];
      before = [];
      requires = [];
      wants = [(operations.network.operations.ready.effects.envoy.outputs.resource)];
    };
    supervision = {
      startup_protocol = "process";
      notification_access = "none";
    };
    readiness = {
      mechanism = "process-running";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    credentials =
      if configuredCredentials == []
      then null
      else {
        views =
          builtins.map (name: {
            inherit name;
            inherit (cfg.credentials.${name}) encrypted;
            reference = operations.credential.operations.deliver.effects."envoy-${name}".outputs.path;
            optional = false;
          })
          configuredCredentials;
      };
    configuration.views = [
      {
        name = "bootstrap";
        source = operations.configuration.operations.file.effects.envoy.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "state";
        source = operations.filesystem.operations.directory.effects.envoy-state.outputs.path;
        access = "read-write";
      }
      {
        name = "logs";
        source = operations.filesystem.operations.directory.effects.envoy-logs.outputs.path;
        access = "read-write";
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = {
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0027";
    };
    isolation = {
      privilege = "privileged";
      filesystem = "read-only-system";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
    resources.open_files = {
      kind = "maximum";
      value = 1048576;
    };
  };
in {
  options.aos.envoy = {
    enable = lib.mkOption {
      type = types.bool;
      default = false;
      description = "Enable the Envoy proxy service.";
    };

    node = lib.mkOption {
      type = nodeType;
      default = {};
      description = "The Envoy node identity advertised to xDS servers.";
    };

    listeners = lib.mkOption {
      type = envoyTypes.listeners;
      default = {};
      extensible = true;
      description = "The statically configured listeners.";
    };

    clusters = lib.mkOption {
      type = envoyTypes.clusters;
      default = {};
      extensible = true;
      description = "The statically configured upstream clusters.";
    };

    dynamicResources = lib.mkOption {
      type = dynamicResourcesType;
      default = {};
      description = "The xDS dynamic-resource configuration.";
    };

    runtimeLayers = lib.mkOption {
      type = envoyTypes.runtimeLayers;
      default = {};
      extensible = true;
      description = "Static, non-secret Envoy runtime layers.";
    };

    admin = lib.mkOption {
      type = adminType;
      default = {};
      description = "The local Envoy administration interface.";
    };

    telemetry = lib.mkOption {
      type = telemetryType;
      default = {};
      description = "Envoy telemetry sinks and tags.";
    };

    credentials = lib.mkOption {
      type = credentialReferences;
      default = {};
      description = "Typed credential resources used by static TLS contexts.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."envoy.main" = lib.mkDefault (service // {enable = lib.mkDefault cfg.enable;});

      assertions = [
        {
          assertion = !serviceEnabled || cfg.listeners != {} || cfg.dynamicResources.listenersFromAds;
          message = "envoy.enable requires at least one static listener or listenersFromAds";
        }
        {
          assertion = !serviceEnabled || builtins.length listenerSockets == builtins.length (lib.unique listenerSockets);
          message = "envoy.listeners must not bind duplicate protocol/address/port tuples";
        }
        {
          assertion = !serviceEnabled || builtins.all (chain: (chain.virtualHosts != {}) != (chain.tcpProxyCluster != null)) allChains;
          message = "each Envoy filter chain must configure exactly one of virtualHosts or tcpProxyCluster";
        }
        {
          assertion = !serviceEnabled || builtins.all (route: routeActionCount route == 1) allRoutes;
          message = "each Envoy route must configure exactly one action";
        }
        {
          assertion = !serviceEnabled || builtins.all (route: routeMatchCount route == 1) allRoutes;
          message = "each Envoy route must configure exactly one of prefix, path, or safeRegex";
        }
        {
          assertion =
            !serviceEnabled
            || (
              builtins.all (certificateSourceValid true) downstreamTls
              && builtins.all (certificateSourceValid false) upstreamTls
            );
          message = "Envoy TLS certificate sources must be one SDS secret or a complete certificate/private-key credential pair";
        }
        {
          assertion =
            !serviceEnabled
            || builtins.all
            (name:
              cfg.credentials ? ${name}
              && credentialConfigured cfg.credentials.${name})
            usedCredentials;
          message = "each Envoy TLS credential handle must have a typed envoy.credentials resource";
        }
        {
          assertion = !serviceEnabled || builtins.all (name: builtins.elem name credentialNames) (builtins.attrNames cfg.credentials);
          message = "envoy.credentials contains an unknown credential handle";
        }
        {
          assertion = !serviceEnabled || builtins.all (tls: !tls.requireClientCertificate || validationSourceCount tls == 1) downstreamTls;
          message = "Envoy downstream client-certificate verification requires exactly one CA credential or SDS validation context";
        }
        {
          assertion = !serviceEnabled || builtins.all (tls: validationSourceCount tls == 1) upstreamTls;
          message = "Envoy upstream TLS requires exactly one CA credential or SDS validation context";
        }
        {
          assertion = !serviceEnabled || !builtins.any (tls: tls.sdsSecret != null || tls.validationSdsSecret != null) allTls || cfg.dynamicResources.enableAds;
          message = "Envoy SDS secret references require dynamicResources.enableAds";
        }
        {
          assertion = !serviceEnabled || builtins.all (name: cfg.clusters ? ${name} || cfg.dynamicResources.clustersFromAds) referencedClusters;
          message = "Envoy routes and TCP proxies may reference only configured clusters unless CDS is enabled";
        }
        {
          assertion = !serviceEnabled || (!cfg.dynamicResources.listenersFromAds && !cfg.dynamicResources.clustersFromAds) || cfg.dynamicResources.enableAds;
          message = "Envoy LDS/CDS over ADS requires dynamicResources.enableAds";
        }
        {
          assertion = !serviceEnabled || !cfg.dynamicResources.enableAds || cfg.clusters ? ${cfg.dynamicResources.adsCluster};
          message = "Envoy ADS requires a static cluster named by dynamicResources.adsCluster";
        }
        {
          assertion = !serviceEnabled || !cfg.admin.enable || cfg.admin.address == "127.0.0.1" || cfg.admin.address == "::1";
          message = "Envoy admin is restricted to a loopback address";
        }
      ];
    }
    (lib.mkIf serviceEnabled {
      aos.abilities = {
        filesystem.operations.directory.effects = {
          envoy-state = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-pkg-envoy";
              mode = "0750";
            };
          };
          envoy-logs = {
            lifetime = "persistent";
            input = {
              path = "/var/log/aos-pkg-envoy";
              mode = "0750";
            };
          };
        };
        network.operations.ready.effects.envoy.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        credential.operations.deliver.effects = builtins.listToAttrs (builtins.map (name: {
            name = "envoy-${name}";
            value.input = cfg.credentials.${name};
          })
          configuredCredentials);
        configuration.operations.file.effects.envoy.input = {
          path = "/etc/aos/packages/envoy/bootstrap.json";
          format = "json";
          value = renderedBootstrap;
          mode = "0444";
        };
      };
    })
    (lib.mkIf (serviceEnabled && adminLogEnabled) {
      aos.abilities.filesystem.operations.view.effects.envoy-admin-log.input = {
        sourcePath = operations.filesystem.operations.directory.effects.envoy-logs.outputs.path;
        relativePath = "admin-access.log";
      };
    })
  ];
}
