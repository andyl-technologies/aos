##! Pure rendering from the typed Envoy option tree to bootstrap JSON data.
{lib}: let
  duration = seconds: "${toString seconds}s";
  credentialFile = handle: "/run/credentials/envoy.service/${handle}";
  named = attrs: builtins.map (name: attrs.${name}) (builtins.attrNames attrs);
  optional = condition: attrs: lib.optionalAttrs condition attrs;

  renderTls = direction: tls: let
    usingSds = tls.sdsSecret != null;
    certificate = tls.certificateCredential;
    privateKey = tls.privateKeyCredential;
    common =
      optional (tls.alpn != []) {alpn_protocols = tls.alpn;}
      // optional usingSds {
        tls_certificate_sds_secret_configs = [
          {
            name = tls.sdsSecret;
            sds_config.ads = {};
          }
        ];
      }
      // optional (!usingSds && certificate != null) {
        tls_certificates = [
          {
            certificate_chain.filename = credentialFile certificate;
            private_key.filename = credentialFile privateKey;
          }
        ];
      }
      // optional (tls.validationCaCredential != null) {
        validation_context = {
          trusted_ca.filename = credentialFile tls.validationCaCredential;
        };
      }
      // optional (tls.validationSdsSecret != null) {
        validation_context_sds_secret_config = {
          name = tls.validationSdsSecret;
          sds_config.ads = {};
        };
      };
  in
    common
    // optional (direction == "upstream" && tls.sni != null) {sni = tls.sni;};

  renderRouteMatch = match:
    optional (match.prefix != null) {prefix = match.prefix;}
    // optional (match.path != null) {path = match.path;}
    // optional (match.safeRegex != null) {
      safe_regex = {
        google_re2 = {};
        regex = match.safeRegex;
      };
    }
    // optional (match.headers != {}) {
      headers =
        lib.mapAttrsToList (name: value: {
          inherit name;
          exact_match = value;
        })
        match.headers;
    };

  renderRedirect = value:
    optional value.https {https_redirect = true;}
    // optional (value.host != null) {host_redirect = value.host;}
    // optional (value.port != null) {port_redirect = value.port;}
    // {response_code = "MOVED_PERMANENTLY";}
    // (
      if value.responseCode == 302
      then {response_code = "FOUND";}
      else if value.responseCode == 303
      then {response_code = "SEE_OTHER";}
      else if value.responseCode == 307
      then {response_code = "TEMPORARY_REDIRECT";}
      else if value.responseCode == 308
      then {response_code = "PERMANENT_REDIRECT";}
      else {response_code = "MOVED_PERMANENTLY";}
    );

  renderRoute = route: let
    routeAction =
      optional (route.cluster != null) {cluster = route.cluster;}
      // optional (route.weightedClusters != {}) {
        weighted_clusters.clusters = lib.mapAttrsToList (name: weight: {inherit name weight;}) route.weightedClusters;
      }
      // {timeout = duration route.timeoutSeconds;}
      // optional (route.prefixRewrite != null) {prefix_rewrite = route.prefixRewrite;}
      // optional (route.retryCount > 0) {
        retry_policy = {
          retry_on = "connect-failure,reset";
          num_retries = route.retryCount;
        };
      };
  in
    {
      inherit (route) name;
      match = renderRouteMatch route.match;
    }
    // optional (route.cluster != null || route.weightedClusters != {}) {route = routeAction;}
    // optional (route.directResponse != null) {
      direct_response =
        {
          status = route.directResponse.status;
        }
        // optional (route.directResponse.body != "") {
          body.inline_string = route.directResponse.body;
        };
    }
    // optional (route.redirect != null) {redirect = renderRedirect route.redirect;};

  headerAdds = attrs:
    lib.mapAttrsToList (key: value: {
      header = {inherit key value;};
      append_action = "OVERWRITE_IF_EXISTS_OR_ADD";
    })
    attrs;

  renderVirtualHost = host:
    {
      inherit (host) name domains;
      routes = builtins.map renderRoute (named host.routes);
    }
    // optional (host.requestHeaders != {}) {request_headers_to_add = headerAdds host.requestHeaders;}
    // optional (host.responseHeaders != {}) {response_headers_to_add = headerAdds host.responseHeaders;};

  renderFilterChain = chain: let
    filterChainMatch =
      optional (chain.serverNames != []) {server_names = chain.serverNames;}
      // optional (chain.transportProtocol != null) {transport_protocol = chain.transportProtocol;}
      // optional (chain.applicationProtocols != []) {application_protocols = chain.applicationProtocols;};
    httpManager = {
      name = "envoy.filters.network.http_connection_manager";
      typed_config =
        {
          "@type" = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
          stat_prefix = "listener_${chain.name}";
          route_config = {
            name = "routes_${chain.name}";
            virtual_hosts = builtins.map renderVirtualHost (named chain.virtualHosts);
          };
          http_filters = [
            {
              name = "envoy.filters.http.router";
              typed_config."@type" = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router";
            }
          ];
        }
        // optional (chain.requestTimeoutSeconds > 0) {
          request_timeout = duration chain.requestTimeoutSeconds;
        };
    };
    tcpProxy = {
      name = "envoy.filters.network.tcp_proxy";
      typed_config = {
        "@type" = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";
        stat_prefix = "tcp_${chain.name}";
        cluster = chain.tcpProxyCluster;
      };
    };
  in
    {
      inherit (chain) name;
      filters = [
        (
          if chain.tcpProxyCluster != null
          then tcpProxy
          else httpManager
        )
      ];
    }
    // optional (filterChainMatch != {}) {filter_chain_match = filterChainMatch;}
    // optional (chain.tls != null) {
      transport_socket = {
        name = "envoy.transport_sockets.tls";
        typed_config =
          {
            "@type" = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext";
            common_tls_context = renderTls "downstream" chain.tls;
          }
          // optional chain.tls.requireClientCertificate {require_client_certificate = true;};
      };
    };

  renderListener = listener: {
    inherit (listener) name transparent;
    address.socket_address = {
      inherit (listener) address;
      port_value = listener.port;
      protocol = listener.protocol;
    };
    filter_chains = builtins.map renderFilterChain (named listener.filterChains);
  };

  renderEndpoint = endpoint: {
    endpoint.address.socket_address = {
      inherit (endpoint) address;
      port_value = endpoint.port;
    };
    load_balancing_weight = endpoint.weight;
  };

  renderEndpointGroups = endpoints:
    builtins.map (group: let
      first = builtins.head group;
    in
      {
        priority = first.priority;
        lb_endpoints = builtins.map renderEndpoint group;
      }
      // optional (first.locality != null) {locality.zone = first.locality;}) (
      builtins.attrValues (builtins.groupBy (endpoint: "${toString endpoint.priority}:${
          if endpoint.locality == null
          then ""
          else endpoint.locality
        }")
        endpoints)
    );

  renderHealthCheck = check:
    {
      timeout = duration check.timeoutSeconds;
      interval = duration check.intervalSeconds;
      healthy_threshold = check.healthyThreshold;
      unhealthy_threshold = check.unhealthyThreshold;
    }
    // (
      if check.type == "http"
      then {http_health_check.path = check.path;}
      else if check.type == "grpc"
      then {grpc_health_check.service_name = check.serviceName;}
      else {tcp_health_check = {};}
    );

  renderCluster = cluster:
    {
      inherit (cluster) name;
      type = cluster.discovery;
      connect_timeout = duration cluster.connectTimeoutSeconds;
      lb_policy = cluster.lbPolicy;
      circuit_breakers.thresholds = [
        {
          priority = "DEFAULT";
          max_connections = cluster.circuitBreakers.maxConnections;
          max_pending_requests = cluster.circuitBreakers.maxPendingRequests;
          max_requests = cluster.circuitBreakers.maxRequests;
          max_retries = cluster.circuitBreakers.maxRetries;
        }
      ];
    }
    // optional (cluster.discovery != "EDS") {
      load_assignment = {
        cluster_name = cluster.name;
        endpoints = renderEndpointGroups cluster.endpoints;
      };
    }
    // optional (cluster.discovery == "EDS") {
      eds_cluster_config = {
        eds_config.ads = {};
        service_name =
          if cluster.edsServiceName == null
          then cluster.name
          else cluster.edsServiceName;
      };
    }
    // optional cluster.http2 {http2_protocol_options = {};}
    // optional (cluster.healthChecks != []) {health_checks = builtins.map renderHealthCheck cluster.healthChecks;}
    // optional (cluster.tls != null) {
      transport_socket = {
        name = "envoy.transport_sockets.tls";
        typed_config =
          {
            "@type" = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext";
            common_tls_context = renderTls "upstream" cluster.tls;
          }
          // optional (cluster.tls.sni != null) {sni = cluster.tls.sni;};
      };
    };

  renderRuntimeLayer = layer: {
    inherit (layer) name;
    static_layer = layer.values;
  };
in
  cfg: let
    staticResources = {
      listeners = builtins.map renderListener (named cfg.listeners);
      clusters = builtins.map renderCluster (named cfg.clusters);
    };
    dynamicResources =
      optional cfg.dynamicResources.enableAds {
        ads_config = {
          api_type = "GRPC";
          transport_api_version = "V3";
          grpc_services = [{envoy_grpc.cluster_name = cfg.dynamicResources.adsCluster;}];
          set_node_on_first_message_only = true;
        };
      }
      // optional cfg.dynamicResources.listenersFromAds {lds_config.ads = {};}
      // optional cfg.dynamicResources.clustersFromAds {cds_config.ads = {};};
    admin = {
      address.socket_address = {
        address = cfg.admin.address;
        port_value = cfg.admin.port;
      };
      access_log_path = cfg.admin.accessLogPath;
    };
    statsSinks = lib.optionals (cfg.telemetry.statsd != null) [
      {
        name = "envoy.stat_sinks.statsd";
        typed_config = {
          "@type" = "type.googleapis.com/envoy.config.metrics.v3.StatsdSink";
          address.socket_address = {
            inherit (cfg.telemetry.statsd) address;
            port_value = cfg.telemetry.statsd.port;
          };
        };
      }
    ];
  in
    {
      node =
        {
          id = cfg.node.id;
          cluster = cfg.node.cluster;
        }
        // optional (cfg.node.metadata != {}) {metadata = cfg.node.metadata;};
      static_resources = staticResources;
    }
    // optional (dynamicResources != {}) {dynamic_resources = dynamicResources;}
    // optional cfg.admin.enable {inherit admin;}
    // optional (cfg.runtimeLayers != {}) {
      layered_runtime.layers = builtins.map renderRuntimeLayer (named cfg.runtimeLayers);
    }
    // optional (statsSinks != []) {stats_sinks = statsSinks;}
    // optional (cfg.telemetry.statsPrefix != "") {
      stats_config.stats_tags = [
        {
          tag_name = "aos.prefix";
          fixed_value = cfg.telemetry.statsPrefix;
        }
      ];
    }
