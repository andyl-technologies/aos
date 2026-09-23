##! Package-owned, typed Envoy service configuration interface.
{
  config,
  lib,
  ...
}: let
  envoyTypes = import ./types.nix {inherit lib;};
  render = import ./render.nix {inherit lib;};
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  credentialNames = [
    "tls-certificate"
    "tls-private-key"
    "validation-ca"
  ];
  credentialReference = serviceTypes.credentialReference;
  credentialReferences = abilityTypes.map {
    keyMaxLength = 64;
    maxEntries = builtins.length credentialNames;
    value = credentialReference;
  };
  nodeType = abilityTypes.record {
    fields = {
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
  dynamicResourcesType = abilityTypes.record {
    fields = {
      enableAds = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether to configure aggregated discovery service.";
      };
      adsCluster = {
        type = envoyTypes.nonEmpty;
        default = "xds-control-plane";
        description = "The static cluster serving ADS and SDS.";
      };
      listenersFromAds = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether listeners are obtained through LDS over ADS.";
      };
      clustersFromAds = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether clusters are obtained through CDS over ADS.";
      };
    };
  };
  adminType = abilityTypes.record {
    fields = {
      enable = {
        type = abilityTypes.boolean;
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
        type = abilityTypes.enum ["disabled" "service-log"];
        default = "service-log";
        description = "Whether administration requests are discarded or written to the service-owned log storage.";
      };
    };
  };
  telemetryType = abilityTypes.record {
    fields = {
      statsPrefix = {
        type = abilityTypes.runtimeString;
        default = "";
        description = "An optional fixed tag attached to emitted metrics.";
      };
      statsd = {
        type = abilityTypes.optional envoyTypes.socketAddress;
        default = null;
        description = "An optional StatsD sink.";
      };
    };
  };
  cfg = envoyTypes.normalize config.envoy;
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
      cfg.credentials ? ${name}
      && serviceManagement.credentialReferenceConfigured cfg.credentials.${name})
    usedCredentials;
  isDeferredResult = value:
    builtins.isAttrs value
    && (value._type or null) == "aos-request-output-reference";
  documentKind = value:
    if isDeferredResult value || builtins.isString value
    then "string"
    else if value == null
    then "null"
    else if builtins.isBool value
    then "boolean"
    else if builtins.isInt value
    then "integer"
    else if builtins.isList value
    then "array"
    else if builtins.isAttrs value
    then "object"
    else throw "Envoy rendered an unsupported bootstrap value";
  valueTypeFor = values: let
    nonNullValues = builtins.filter (value: value != null) values;
    kinds = lib.unique (builtins.map documentKind nonNullValues);
    typeForKind = kind: let
      matching = builtins.filter (value: documentKind value == kind) nonNullValues;
    in
      if kind == "boolean"
      then abilityTypes.boolean
      else if kind == "integer"
      then
        abilityTypes.integer {
          minimum = -abilityTypes.limits.maxSafeInteger;
          maximum = abilityTypes.limits.maxSafeInteger;
        }
      else if kind == "string"
      then
        if builtins.any isDeferredResult matching
        then abilityTypes.deferredResult abilityTypes.executionPath
        else abilityTypes.runtimeString
      else if kind == "array"
      then let
        elements = lib.concatLists matching;
      in
        abilityTypes.list {
          element =
            if elements == []
            then abilityTypes.runtimeString
            else valueTypeFor elements;
          maxItems = abilityTypes.limits.maxCollectionItems;
        }
      else if kind == "object"
      then let
        keys = lib.unique (lib.concatLists (builtins.map builtins.attrNames matching));
        presentValues = key:
          builtins.map (value: value.${key}) (builtins.filter (value: builtins.hasAttr key value) matching);
      in
        abilityTypes.documentRecord {
          keyMaxLength = 1024;
          fields = builtins.listToAttrs (builtins.map (key: {
              name = key;
              value = valueTypeFor (presentValues key);
            })
            keys);
          optional =
            builtins.filter
            (key: builtins.any (value: !(builtins.hasAttr key value)) matching)
            keys;
        }
      else throw "Envoy bootstrap type inference encountered an unsupported value kind";
    concrete =
      if kinds == []
      then abilityTypes.runtimeString
      else if builtins.length kinds == 1
      then typeForKind (builtins.head kinds)
      else abilityTypes.disjointUnion (builtins.map typeForKind kinds);
  in
    if builtins.length nonNullValues != builtins.length values
    then abilityTypes.optional concrete
    else concrete;
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "envoy";
      inherit key interface parameters;
    };
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/envoy";
      inherit arguments;
    };
    ignore_failure = false;
  };
  credentialPaths = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = resultOf "credential-${name}" "credential-path";
    })
    configuredCredentials);
  adminLogEnabled = cfg.admin.enable && cfg.admin.accessLog == "service-log";
  adminLogPath =
    if adminLogEnabled
    then resultOf "admin-log-view" "planned-path"
    else null;
  renderedBootstrap =
    render {
      inherit adminLogPath credentialPaths;
    }
    cfg;
  storage = serviceManagement.forProducers {
    consumerInstance = "envoy";
    interface = serviceManagement.interfaces.persistentStorageAllocation;
    producers = [
      {
        key = "state-storage";
        parameters = {
          name = "state";
          purpose = "state";
          mode = "0750";
        };
      }
      {
        key = "log-storage";
        parameters = {
          name = "logs";
          purpose = "logs";
          mode = "0750";
        };
      }
    ];
  };
  adminLogView = producer "admin-log-view" serviceManagement.interfaces.storageView {
    name = "admin-access-log";
    source = resultOf "log-storage" "resource";
    source_path = resultOf "log-storage" "planned-path";
    access = "read-write";
    relative_path = "admin-access.log";
  };
  networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
    scope = "configured-connectivity";
    address_families = ["ipv4" "ipv6"];
  };
  credentialRequests = serviceManagement.forCredentialReferences {
    consumerInstance = "envoy";
    references =
      builtins.map (name: {
        key = "credential-${name}";
        inherit name;
        reference = cfg.credentials.${name};
      })
      configuredCredentials;
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "envoy";
    declaration = {
      name = "bootstrap-configuration";
      source = serviceManagement.structuredSource {
        format = "json";
        valueType = valueTypeFor [renderedBootstrap];
        value = renderedBootstrap;
      };
      mode = "0444";
    };
  };
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
      operation_profile = "restricted";
      isolated_identity_mapping = "none";
    };
    consumerInstance = "envoy";
    service = "main";
    lifecycle = {
      description = "Envoy proxy";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [(command ["--mode" "validate" "--config-path" (resultOf "bootstrap-configuration" "planned-path")])];
      start = [(command ["--disable-hot-restart" "--config-path" (resultOf "bootstrap-configuration" "planned-path")])];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_token = cfg.restartToken;
      restart_delay_millis = 2000;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 60000;
    };
    dependencies = {
      after = [(resultOf "network-readiness" "resource")];
      before = [];
      requires = [];
      wants = [(resultOf "network-readiness" "resource")];
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
            reference = resultOf "credential-${name}" "credential-path";
            optional = false;
          })
          configuredCredentials;
      };
    configuration.views = [
      {
        name = "bootstrap";
        source = resultOf "bootstrap-configuration" "planned-path";
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "state";
        source = resultOf "state-storage" "planned-path";
        access = "read-write";
      }
      {
        name = "logs";
        source = resultOf "log-storage" "planned-path";
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
  options.envoy = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
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

    restartToken = lib.mkOption {
      type = abilityTypes.optional serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services."envoy.main" = service // {enable = cfg.enable;};

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
              && serviceManagement.credentialReferenceConfigured cfg.credentials.${name})
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
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [storage networkReadiness configuration];
      enabled = serviceEnabled;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [credentialRequests];
      enabled = serviceEnabled && configuredCredentials != [];
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [adminLogView];
      enabled = serviceEnabled && adminLogEnabled;
    })
  ];
}
