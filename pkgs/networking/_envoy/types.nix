##! Native mergeable option contracts for Envoy configuration.
{lib}: let
  types = lib.types;
  runtimeString = types.str;
  nonEmpty = types.strMatching ".+";
  positiveInt = types.ints.between 1 9007199254740991;
  nonNegativeInt = types.ints.between 0 9007199254740991;
  port = types.ints.between 1 65535;
  statusCode = types.enum [301 302 303 307 308];
  listOf = types.listOf;
  mapOf = types.attrsOf;
  nullable = type: description: {
    type = types.nullOr type;
    default = null;
    inherit description;
  };
  runtimeValue = types.oneOf [types.bool (types.ints.between (-9007199254740991) 9007199254740991) types.str];

  socketAddress = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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

  tlsContext = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      sdsSecret = nullable nonEmpty "The SDS secret resource name; never secret material.";
      validationSdsSecret = nullable nonEmpty "The SDS validation-context resource name; never CA material.";
      certificateCredential = nullable (types.enum ["tls-certificate"]) "The credential handle containing the PEM certificate chain.";
      privateKeyCredential = nullable (types.enum ["tls-private-key"]) "The credential handle containing the PEM private key.";
      validationCaCredential = nullable (types.enum ["validation-ca"]) "The credential handle containing trusted CA certificates.";
      requireClientCertificate = {
        type = types.bool;
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

  directResponse = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      status = {
        type = types.ints.between 100 599;
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

  redirect = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      https = {
        type = types.bool;
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

  routeMatch = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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

  route = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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

  virtualHost = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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

  filterChain = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      serverNames = {
        type = listOf nonEmpty;
        default = [];
        description = "The SNI names selecting this filter chain.";
      };
      transportProtocol = nullable (types.enum ["raw_buffer" "tls"]) "An optional transport-protocol match.";
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

  listener = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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
        type = types.enum ["TCP" "UDP"];
        default = "TCP";
        description = "The listener socket protocol.";
      };
      transparent = {
        type = types.bool;
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

  endpoint = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
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

  healthCheck = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      type = {
        type = types.enum ["tcp" "http" "grpc"];
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

  circuitBreakers = types.submodule {
    options = builtins.mapAttrs (_: default:
      lib.mkOption {
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

  cluster = types.submodule {
    options = lib.mapAttrs (_: definition: lib.mkOption definition) {
      discovery = {
        type = types.enum ["STATIC" "STRICT_DNS" "LOGICAL_DNS" "EDS"];
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
        type = types.enum ["ROUND_ROBIN" "LEAST_REQUEST" "RING_HASH" "RANDOM" "MAGLEV"];
        default = "ROUND_ROBIN";
        description = "The load-balancing policy.";
      };
      http2 = {
        type = types.bool;
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

  runtimeLayer = types.submodule {
    options.values = lib.mkOption {
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
