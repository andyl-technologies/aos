##! Portable option contracts for the Envoy package configuration module.
{lib}: let
  abilityTypes = lib.abilities.types;

  runtimeString = abilityTypes.runtimeString;
  nonEmpty = abilityTypes.refined {
    name = "non-empty Envoy string";
    description = "a non-empty Envoy configuration string";
    type = runtimeString;
    predicate = value: builtins.match ".+" value != null;
  };
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  nonNegativeInt = abilityTypes.integer {
    minimum = 0;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  statusCode = abilityTypes.refined {
    name = "Envoy redirect status";
    description = "an HTTP redirect status supported by Envoy";
    type = abilityTypes.integer {
      minimum = 301;
      maximum = 308;
    };
    predicate = value: builtins.elem value [301 302 303 307 308];
  };
  listOf = element:
    abilityTypes.list {
      inherit element;
      maxItems = 4096;
    };
  mapOf = value:
    abilityTypes.map {
      keyMaxLength = 1024;
      maxEntries = 4096;
      inherit value;
    };
  nullable = type: description: {
    type = abilityTypes.optional type;
    default = null;
    inherit description;
  };

  runtimeValue = abilityTypes.disjointUnion [
    abilityTypes.boolean
    (abilityTypes.integer {
      minimum = -abilityTypes.limits.maxSafeInteger;
      maximum = abilityTypes.limits.maxSafeInteger;
    })
    runtimeString
  ];

  socketAddress = abilityTypes.record {
    fields = {
      address = {
        type = nonEmpty;
        default = "127.0.0.1";
        description = "The IPv4, IPv6, or DNS socket address.";
      };
      port = {
        type = port;
        description = "The socket port.";
      };
    };
  };

  tlsContext = abilityTypes.record {
    fields = {
      sdsSecret = nullable nonEmpty "The SDS secret resource name; never secret material.";
      validationSdsSecret = nullable nonEmpty "The SDS validation-context resource name; never CA material.";
      certificateCredential = nullable (abilityTypes.enum ["tls-certificate"]) "The credential handle containing the PEM certificate chain.";
      privateKeyCredential = nullable (abilityTypes.enum ["tls-private-key"]) "The credential handle containing the PEM private key.";
      validationCaCredential = nullable (abilityTypes.enum ["validation-ca"]) "The credential handle containing trusted CA certificates.";
      requireClientCertificate = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether a downstream peer must present a valid certificate.";
      };
      sni = nullable nonEmpty "The SNI server name used for an upstream TLS connection.";
      alpn = {
        type = listOf nonEmpty;
        default = [];
        description = "The ordered ALPN protocol names.";
      };
    };
  };

  directResponse = abilityTypes.record {
    fields = {
      status = {
        type = abilityTypes.integer {
          minimum = 100;
          maximum = 599;
        };
        default = 200;
        description = "The HTTP response status.";
      };
      body = {
        type = runtimeString;
        default = "";
        description = "The non-secret inline response body.";
      };
    };
  };

  redirect = abilityTypes.record {
    fields = {
      https = {
        type = abilityTypes.boolean;
        default = true;
        description = "Whether the redirect changes the scheme to HTTPS.";
      };
      host = nullable nonEmpty "An optional replacement host.";
      port = nullable port "An optional replacement port.";
      responseCode = {
        type = statusCode;
        default = 301;
        description = "The redirect response status.";
      };
    };
  };

  routeMatch = abilityTypes.record {
    fields = {
      prefix = nullable runtimeString "The path prefix to match." // {default = "/";};
      path = nullable runtimeString "The exact path to match.";
      safeRegex = nullable nonEmpty "The RE2-compatible path expression to match.";
      headers = {
        type = mapOf nonEmpty;
        default = {};
        description = "Exact HTTP header matches.";
      };
    };
  };

  route = abilityTypes.record {
    fields = {
      match = {
        type = routeMatch;
        default = {};
        description = "The request match.";
      };
      cluster = nullable nonEmpty "The destination cluster.";
      weightedClusters = {
        type = mapOf positiveInt;
        default = {};
        description = "Destination clusters and their relative weights.";
      };
      directResponse = nullable directResponse "An immediate local response.";
      redirect = nullable redirect "An HTTP redirect action.";
      timeoutSeconds = {
        type = nonNegativeInt;
        default = 15;
        description = "The upstream request timeout in seconds; zero disables it.";
      };
      prefixRewrite = nullable runtimeString "An optional path prefix rewrite.";
      retryCount = {
        type = nonNegativeInt;
        default = 0;
        description = "The number of retry attempts for connect and reset failures.";
      };
    };
  };

  virtualHost = abilityTypes.record {
    fields = {
      domains = nullable (listOf nonEmpty) "The authority patterns accepted by this virtual host.";
      routes = {
        type = mapOf route;
        default = {};
        description = "The ordered route map (lexicographic by route name).";
      };
      requestHeaders = {
        type = mapOf runtimeString;
        default = {};
        description = "Request headers added at the virtual-host boundary.";
      };
      responseHeaders = {
        type = mapOf runtimeString;
        default = {};
        description = "Response headers added at the virtual-host boundary.";
      };
    };
  };

  filterChain = abilityTypes.record {
    fields = {
      serverNames = {
        type = listOf nonEmpty;
        default = [];
        description = "The SNI names selecting this filter chain.";
      };
      transportProtocol = nullable (abilityTypes.enum ["raw_buffer" "tls"]) "An optional transport-protocol match.";
      applicationProtocols = {
        type = listOf nonEmpty;
        default = [];
        description = "The ALPN protocol matches.";
      };
      tls = nullable tlsContext "The downstream TLS context using credentials or SDS.";
      virtualHosts = {
        type = mapOf virtualHost;
        default = {};
        description = "HTTP virtual hosts served by this filter chain.";
      };
      tcpProxyCluster = nullable nonEmpty "The raw TCP proxy destination cluster.";
      requestTimeoutSeconds = {
        type = nonNegativeInt;
        default = 0;
        description = "The HTTP connection-manager request timeout; zero disables it.";
      };
    };
  };

  listener = abilityTypes.record {
    fields = {
      address = {
        type = nonEmpty;
        default = "127.0.0.1";
        description = "The listener bind address.";
      };
      port = {
        type = port;
        description = "The listener bind port.";
      };
      protocol = {
        type = abilityTypes.enum ["TCP" "UDP"];
        default = "TCP";
        description = "The listener socket protocol.";
      };
      transparent = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether the listener accepts transparently redirected traffic.";
      };
      filterChains = {
        type = mapOf filterChain;
        default = {};
        description = "The listener filter chains.";
      };
    };
  };

  endpoint = abilityTypes.record {
    fields = {
      address = {
        type = nonEmpty;
        description = "The endpoint IP address or DNS name.";
      };
      port = {
        type = port;
        description = "The endpoint port.";
      };
      weight = {
        type = positiveInt;
        default = 1;
        description = "The load-balancing weight.";
      };
      priority = {
        type = nonNegativeInt;
        default = 0;
        description = "The failover priority.";
      };
      locality = nullable nonEmpty "An optional locality label.";
    };
  };

  healthCheck = abilityTypes.record {
    fields = {
      type = {
        type = abilityTypes.enum ["tcp" "http" "grpc"];
        default = "tcp";
        description = "The active health-check protocol.";
      };
      path = {
        type = nonEmpty;
        default = "/healthz";
        description = "The HTTP health-check path.";
      };
      serviceName = {
        type = runtimeString;
        default = "";
        description = "The gRPC health-check service name.";
      };
      intervalSeconds = {
        type = positiveInt;
        default = 10;
        description = "The interval between checks.";
      };
      timeoutSeconds = {
        type = positiveInt;
        default = 3;
        description = "The check timeout.";
      };
      healthyThreshold = {
        type = positiveInt;
        default = 2;
        description = "The consecutive successes required for health.";
      };
      unhealthyThreshold = {
        type = positiveInt;
        default = 3;
        description = "The consecutive failures required for unhealth.";
      };
    };
  };

  circuitBreakers = abilityTypes.record {
    fields =
      builtins.mapAttrs (_: default: {
        type = positiveInt;
        inherit default;
        description = "The default-priority circuit-breaker threshold.";
      }) {
        maxConnections = 1024;
        maxPendingRequests = 1024;
        maxRequests = 1024;
        maxRetries = 3;
      };
  };

  cluster = abilityTypes.record {
    fields = {
      discovery = {
        type = abilityTypes.enum ["STATIC" "STRICT_DNS" "LOGICAL_DNS" "EDS"];
        default = "STATIC";
        description = "The endpoint discovery policy.";
      };
      endpoints = {
        type = listOf endpoint;
        default = [];
        description = "The statically or DNS-resolved endpoints.";
      };
      edsServiceName = nullable nonEmpty "The EDS service name; defaults to the cluster name.";
      connectTimeoutSeconds = {
        type = positiveInt;
        default = 5;
        description = "The upstream connection timeout.";
      };
      lbPolicy = {
        type = abilityTypes.enum ["ROUND_ROBIN" "LEAST_REQUEST" "RING_HASH" "RANDOM" "MAGLEV"];
        default = "ROUND_ROBIN";
        description = "The load-balancing policy.";
      };
      http2 = {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether to use HTTP/2 upstream.";
      };
      tls = nullable tlsContext "The upstream TLS context using credentials or SDS.";
      healthChecks = {
        type = listOf healthCheck;
        default = [];
        description = "Active health checks.";
      };
      circuitBreakers = {
        type = circuitBreakers;
        default = {};
        description = "The default-priority circuit-breaker thresholds.";
      };
    };
  };

  runtimeLayer = abilityTypes.record {
    fields.values = {
      type = mapOf runtimeValue;
      default = {};
      description = "Non-secret static runtime keys.";
    };
  };

  listeners = mapOf listener;
  clusters = mapOf cluster;
  runtimeLayers = mapOf runtimeLayer;
  metadata = mapOf runtimeValue;

  withNulls = names: value:
    lib.genAttrs names (_: null) // value;
  normalizeTls = value:
    if value == null
    then null
    else
      withNulls [
        "sdsSecret"
        "validationSdsSecret"
        "certificateCredential"
        "privateKeyCredential"
        "validationCaCredential"
        "sni"
      ]
      value;
  normalizeRoute = name: value:
    (withNulls ["cluster" "directResponse" "redirect" "prefixRewrite"] value)
    // {
      inherit name;
      match = withNulls ["path" "safeRegex"] value.match;
    };
  normalizeVirtualHost = name: value:
    value
    // {
      inherit name;
      domains = value.domains or [name];
      routes = builtins.mapAttrs normalizeRoute value.routes;
    };
  normalizeFilterChain = name: value:
    (withNulls ["transportProtocol" "tls" "tcpProxyCluster"] value)
    // {
      inherit name;
      tls = normalizeTls (value.tls or null);
      virtualHosts = builtins.mapAttrs normalizeVirtualHost value.virtualHosts;
    };
  normalizeListener = name: value:
    value
    // {
      inherit name;
      filterChains = builtins.mapAttrs normalizeFilterChain value.filterChains;
    };
  normalizeEndpoint = value: withNulls ["locality"] value;
  normalizeCluster = name: value:
    (withNulls ["edsServiceName" "tls"] value)
    // {
      inherit name;
      endpoints = builtins.map normalizeEndpoint value.endpoints;
      tls = normalizeTls (value.tls or null);
    };
  normalizeRuntimeLayer = name: value: value // {inherit name;};
  normalize = config:
    config
    // {
      listeners = builtins.mapAttrs normalizeListener config.listeners;
      clusters = builtins.mapAttrs normalizeCluster config.clusters;
      runtimeLayers = builtins.mapAttrs normalizeRuntimeLayer config.runtimeLayers;
      telemetry = config.telemetry // {statsd = config.telemetry.statsd or null;};
    };
in {
  inherit
    cluster
    clusters
    filterChain
    healthCheck
    listener
    listeners
    metadata
    nonEmpty
    normalize
    port
    runtimeLayer
    runtimeLayers
    runtimeValue
    socketAddress
    tlsContext
    virtualHost
    ;
}
