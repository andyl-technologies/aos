##! Typed option contracts for the Envoy package configuration module.
{lib}: let
  inherit (lib) mkOption types;
  nonEmpty = types.strMatching ".+";
  positiveInt = types.addCheck types.int (value: value > 0);
  nonNegativeInt = types.addCheck types.int (value: value >= 0);

  socketAddress = types.submodule {
    config._module.strict = true;
    options = {
      address = mkOption {
        type = nonEmpty;
        default = "127.0.0.1";
        description = "The IPv4, IPv6, or DNS socket address.";
      };
      port = mkOption {
        type = types.port;
        description = "The socket port.";
      };
    };
  };

  tlsContext = types.submodule {
    config._module.strict = true;
    options = {
      sdsSecret = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The SDS secret resource name; never secret material.";
      };
      validationSdsSecret = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The SDS validation-context resource name; never CA material.";
      };
      certificateCredential = mkOption {
        type = types.nullOr (types.enum ["tls-certificate"]);
        default = null;
        description = "The credential handle containing the PEM certificate chain.";
      };
      privateKeyCredential = mkOption {
        type = types.nullOr (types.enum ["tls-private-key"]);
        default = null;
        description = "The credential handle containing the PEM private key.";
      };
      validationCaCredential = mkOption {
        type = types.nullOr (types.enum ["validation-ca"]);
        default = null;
        description = "The credential handle containing trusted CA certificates.";
      };
      requireClientCertificate = mkOption {
        type = types.bool;
        default = false;
        description = "Whether a downstream peer must present a valid certificate.";
      };
      sni = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The SNI server name used for an upstream TLS connection.";
      };
      alpn = mkOption {
        type = types.listOf nonEmpty;
        default = [];
        description = "The ordered ALPN protocol names.";
      };
    };
  };

  directResponse = types.submodule {
    config._module.strict = true;
    options = {
      status = mkOption {
        type = types.addCheck types.int (value: value >= 100 && value <= 599);
        default = 200;
        description = "The HTTP response status.";
      };
      body = mkOption {
        type = types.str;
        default = "";
        description = "The non-secret inline response body.";
      };
    };
  };

  redirect = types.submodule {
    config._module.strict = true;
    options = {
      https = mkOption {
        type = types.bool;
        default = true;
        description = "Whether the redirect changes the scheme to HTTPS.";
      };
      host = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "An optional replacement host.";
      };
      port = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "An optional replacement port.";
      };
      responseCode = mkOption {
        type = types.enum [301 302 303 307 308];
        default = 301;
        description = "The redirect response status.";
      };
    };
  };

  route = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The route name.";
      };
      match = mkOption {
        type = types.submodule {
          config._module.strict = true;
          options = {
            prefix = mkOption {
              type = types.nullOr types.str;
              default = "/";
              description = "The path prefix to match.";
            };
            path = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "The exact path to match.";
            };
            safeRegex = mkOption {
              type = types.nullOr nonEmpty;
              default = null;
              description = "The RE2-compatible path expression to match.";
            };
            headers = mkOption {
              type = types.attrsOf nonEmpty;
              default = {};
              description = "Exact HTTP header matches.";
            };
          };
        };
        default = {};
        description = "The request match.";
      };
      cluster = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The destination cluster.";
      };
      weightedClusters = mkOption {
        type = types.attrsOf positiveInt;
        default = {};
        description = "Destination clusters and their relative weights.";
      };
      directResponse = mkOption {
        type = types.nullOr directResponse;
        default = null;
        description = "An immediate local response.";
      };
      redirect = mkOption {
        type = types.nullOr redirect;
        default = null;
        description = "An HTTP redirect action.";
      };
      timeoutSeconds = mkOption {
        type = nonNegativeInt;
        default = 15;
        description = "The upstream request timeout in seconds; zero disables it.";
      };
      prefixRewrite = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "An optional path prefix rewrite.";
      };
      retryCount = mkOption {
        type = nonNegativeInt;
        default = 0;
        description = "The number of retry attempts for connect and reset failures.";
      };
    };
  });

  virtualHost = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The virtual-host name.";
      };
      domains = mkOption {
        type = types.listOf nonEmpty;
        default = [name];
        description = "The authority patterns accepted by this virtual host.";
      };
      routes = mkOption {
        type = types.attrsOf route;
        default = {};
        description = "The ordered route map (lexicographic by route name).";
      };
      requestHeaders = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = "Request headers added at the virtual-host boundary.";
      };
      responseHeaders = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = "Response headers added at the virtual-host boundary.";
      };
    };
  });

  filterChain = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The filter-chain name.";
      };
      serverNames = mkOption {
        type = types.listOf nonEmpty;
        default = [];
        description = "The SNI names selecting this filter chain.";
      };
      transportProtocol = mkOption {
        type = types.nullOr (types.enum ["raw_buffer" "tls"]);
        default = null;
        description = "An optional transport-protocol match.";
      };
      applicationProtocols = mkOption {
        type = types.listOf nonEmpty;
        default = [];
        description = "The ALPN protocol matches.";
      };
      tls = mkOption {
        type = types.nullOr tlsContext;
        default = null;
        description = "The downstream TLS context using credentials or SDS.";
      };
      virtualHosts = mkOption {
        type = types.attrsOf virtualHost;
        default = {};
        description = "HTTP virtual hosts served by this filter chain.";
      };
      tcpProxyCluster = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The raw TCP proxy destination cluster.";
      };
      requestTimeoutSeconds = mkOption {
        type = nonNegativeInt;
        default = 0;
        description = "The HTTP connection-manager request timeout; zero disables it.";
      };
    };
  });

  listener = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The listener name.";
      };
      address = mkOption {
        type = nonEmpty;
        default = "127.0.0.1";
        description = "The listener bind address.";
      };
      port = mkOption {
        type = types.port;
        description = "The listener bind port.";
      };
      protocol = mkOption {
        type = types.enum ["TCP" "UDP"];
        default = "TCP";
        description = "The listener socket protocol.";
      };
      transparent = mkOption {
        type = types.bool;
        default = false;
        description = "Whether the listener accepts transparently redirected traffic.";
      };
      filterChains = mkOption {
        type = types.attrsOf filterChain;
        default = {};
        description = "The listener filter chains.";
      };
    };
  });

  endpoint = types.submodule {
    config._module.strict = true;
    options = {
      address = mkOption {
        type = nonEmpty;
        description = "The endpoint IP address or DNS name.";
      };
      port = mkOption {
        type = types.port;
        description = "The endpoint port.";
      };
      weight = mkOption {
        type = positiveInt;
        default = 1;
        description = "The load-balancing weight.";
      };
      priority = mkOption {
        type = nonNegativeInt;
        default = 0;
        description = "The failover priority.";
      };
      locality = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "An optional locality label.";
      };
    };
  };

  healthCheck = types.submodule {
    config._module.strict = true;
    options = {
      type = mkOption {
        type = types.enum ["tcp" "http" "grpc"];
        default = "tcp";
        description = "The active health-check protocol.";
      };
      path = mkOption {
        type = nonEmpty;
        default = "/healthz";
        description = "The HTTP health-check path.";
      };
      serviceName = mkOption {
        type = types.str;
        default = "";
        description = "The gRPC health-check service name.";
      };
      intervalSeconds = mkOption {
        type = positiveInt;
        default = 10;
        description = "The interval between checks.";
      };
      timeoutSeconds = mkOption {
        type = positiveInt;
        default = 3;
        description = "The check timeout.";
      };
      healthyThreshold = mkOption {
        type = positiveInt;
        default = 2;
        description = "The consecutive successes required for health.";
      };
      unhealthyThreshold = mkOption {
        type = positiveInt;
        default = 3;
        description = "The consecutive failures required for unhealth.";
      };
    };
  };

  cluster = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The cluster name.";
      };
      discovery = mkOption {
        type = types.enum ["STATIC" "STRICT_DNS" "LOGICAL_DNS" "EDS"];
        default = "STATIC";
        description = "The endpoint discovery policy.";
      };
      endpoints = mkOption {
        type = types.listOf endpoint;
        default = [];
        description = "The statically or DNS-resolved endpoints.";
      };
      edsServiceName = mkOption {
        type = types.nullOr nonEmpty;
        default = null;
        description = "The EDS service name; defaults to the cluster name.";
      };
      connectTimeoutSeconds = mkOption {
        type = positiveInt;
        default = 5;
        description = "The upstream connection timeout.";
      };
      lbPolicy = mkOption {
        type = types.enum ["ROUND_ROBIN" "LEAST_REQUEST" "RING_HASH" "RANDOM" "MAGLEV"];
        default = "ROUND_ROBIN";
        description = "The load-balancing policy.";
      };
      http2 = mkOption {
        type = types.bool;
        default = false;
        description = "Whether to use HTTP/2 upstream.";
      };
      tls = mkOption {
        type = types.nullOr tlsContext;
        default = null;
        description = "The upstream TLS context using credentials or SDS.";
      };
      healthChecks = mkOption {
        type = types.listOf healthCheck;
        default = [];
        description = "Active health checks.";
      };
      circuitBreakers = mkOption {
        type = types.submodule {
          config._module.strict = true;
          options = {
            maxConnections = mkOption {
              type = positiveInt;
              default = 1024;
            };
            maxPendingRequests = mkOption {
              type = positiveInt;
              default = 1024;
            };
            maxRequests = mkOption {
              type = positiveInt;
              default = 1024;
            };
            maxRetries = mkOption {
              type = positiveInt;
              default = 3;
            };
          };
        };
        default = {};
        description = "The default-priority circuit-breaker thresholds.";
      };
    };
  });

  runtimeLayer = types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = mkOption {
        type = nonEmpty;
        default = name;
        readOnly = true;
        description = "The runtime layer name.";
      };
      values = mkOption {
        type = types.attrsOf (types.either types.bool (types.either types.int types.str));
        default = {};
        description = "Non-secret static runtime keys.";
      };
    };
  });
in {
  inherit cluster filterChain healthCheck listener runtimeLayer socketAddress tlsContext virtualHost;
}
