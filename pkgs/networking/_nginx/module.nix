##! Package-owned nginx options and provider-neutral service declarations.
##!
##! The package owns the shared `nginx.*` root. Other authenticated packages
##! may contribute named virtual hosts and upstreams, but global policy and
##! service enablement remain operator/owner-only. TLS key material is never
##! accepted as a Nix string. Typed credential requests appear only when a TLS
##! virtual host uses them, so an HTTP-only service has no credential binding.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.nginx;

  inherit (lib.abilities) pathWithin resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  nonNegativeInt = abilityTypes.integer {
    minimum = 0;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  httpStatus = abilityTypes.integer {
    minimum = 100;
    maximum = 599;
  };
  port = abilityTypes.integer {
    minimum = 1;
    maximum = 65535;
  };
  boundedText = maximum:
    abilityTypes.string {
      maxLength = maximum;
      syntax = null;
    };
  checkedString = name: description: pattern: maximum:
    abilityTypes.refined {
      inherit name description;
      type = boundedText maximum;
      constraints = [
        {
          kind = "string-pattern";
          pattern = pattern;
        }
      ];
    };
  size = checkedString "nginx size" "an nginx byte size" "[0-9]+[kKmMgG]?" 64;
  duration = checkedString "nginx duration" "an nginx duration" "[0-9]+(ms|s|m|h|d)" 64;
  token = checkedString "nginx token" "a whitespace-free nginx token" "[^{};[:space:]]+" 4096;
  serverName = checkedString "nginx server name" "a whitespace-free nginx server name" "[^{};[:space:]]+" 253;
  upstreamAddress = checkedString "nginx upstream address" "a whitespace-free nginx upstream address" "[^{};[:space:]]+" 4096;
  upstreamUri = checkedString "nginx upstream URI" "an absolute upstream URI" "[A-Za-z][A-Za-z0-9+.-]*://[^;[:space:]]+" 4096;
  confinedDirectives = checkedString "confined nginx directives" "nginx directives without braces" "[^{}]*" 1048576;
  documentRoot = abilityTypes.relativePath;
  credentialReference = serviceTypes.credentialReference;

  quote = value: ''"${builtins.replaceStrings ["\\" "\"" "\n" "\r"] ["\\\\" "\\\"" "\\n" ""] value}"'';
  indent = prefix: text:
    prefix + builtins.replaceStrings ["\n"] ["\n${prefix}"] text;
  optionalLine = condition: line:
    if condition
    then "${line}\n"
    else "";
  optionalToken = condition: value:
    if condition
    then value
    else "";
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  optionalFragments = condition: fragments:
    if condition
    then fragments
    else [];
  runtimePath = resultOf "runtime-storage" "planned-path";
  statePath = resultOf "state-storage" "planned-path";
  logPath = resultOf "log-storage" "planned-path";
  documentPath = relativePath:
    pathWithin {
      base = statePath;
      inherit relativePath;
    };

  upstreamServerType = abilityTypes.record {
    fields = {
      address = upstreamAddress;
      weight = positiveInt;
      maxFails = nonNegativeInt;
      failTimeout = duration;
      backup = abilityTypes.boolean;
      down = abilityTypes.boolean;
    };
    optional = ["weight" "maxFails" "failTimeout" "backup" "down"];
  };
  upstreamServers = abilityTypes.list {
    element = upstreamServerType;
    maxItems = 1024;
    unique = false;
    canonicalOrder = false;
  };
  upstreamType = abilityTypes.record {
    fields = {
      servers = upstreamServers;
      keepalive = positiveInt;
      extraConfig = confinedDirectives;
    };
    optional = ["keepalive" "extraConfig"];
  };
  returnType = abilityTypes.record {
    fields = {
      code = httpStatus;
      body = boundedText 65536;
    };
    optional = ["body"];
  };
  orderedTokens = abilityTypes.list {
    element = token;
    maxItems = 256;
    unique = false;
    canonicalOrder = false;
  };
  proxyHeaders = abilityTypes.map {
    keyMaxLength = 256;
    keySyntax = null;
    maxEntries = 256;
    value = boundedText 4096;
  };
  locationType = abilityTypes.record {
    fields = {
      proxyPass = upstreamUri;
      root = documentRoot;
      "return" = returnType;
      tryFiles = orderedTokens;
      proxySetHeaders = proxyHeaders;
      extraConfig = confinedDirectives;
    };
    optional = ["proxyPass" "root" "return" "tryFiles" "proxySetHeaders" "extraConfig"];
  };
  locationMap = abilityTypes.map {
    keyMaxLength = 1024;
    keySyntax = null;
    maxEntries = 1024;
    value = locationType;
  };
  tlsProtocols = abilityTypes.list {
    element = abilityTypes.enum ["TLSv1.2" "TLSv1.3"];
    maxItems = 2;
    unique = true;
    canonicalOrder = true;
  };
  tlsType = abilityTypes.record {
    fields = {
      enable = abilityTypes.boolean;
      protocols = tlsProtocols;
    };
    optional = ["enable" "protocols"];
  };
  listenPorts = abilityTypes.list {
    element = port;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  serverNames = abilityTypes.list {
    element = serverName;
    maxItems = 256;
    unique = true;
    canonicalOrder = true;
  };
  virtualHostType = abilityTypes.record {
    fields = {
      listen = listenPorts;
      serverNames = serverNames;
      root = documentRoot;
      index = orderedTokens;
      locations = locationMap;
      tls = tlsType;
      extraConfig = confinedDirectives;
    };
    optional = ["listen" "serverNames" "root" "index" "locations" "tls" "extraConfig"];
  };
  upstreamMap = abilityTypes.map {
    keyMaxLength = 128;
    keySyntax = null;
    maxEntries = 256;
    value = upstreamType;
  };
  virtualHostMap = abilityTypes.map {
    keyMaxLength = 253;
    keySyntax = null;
    maxEntries = 1024;
    value = virtualHostType;
  };

  normalizeUpstreamServer = server: {
    inherit (server) address;
    weight = server.weight or null;
    maxFails = server.maxFails or 1;
    failTimeout = server.failTimeout or "10s";
    backup = server.backup or false;
    down = server.down or false;
  };
  normalizeUpstream = upstream: {
    servers = builtins.map normalizeUpstreamServer upstream.servers;
    keepalive = upstream.keepalive or null;
    extraConfig = upstream.extraConfig or "";
  };
  normalizeReturn = response:
    if response == null
    then null
    else {
      inherit (response) code;
      body = response.body or "";
    };
  normalizeLocation = location: {
    proxyPass = location.proxyPass or null;
    root = location.root or null;
    "return" = normalizeReturn (location."return" or null);
    tryFiles = location.tryFiles or [];
    proxySetHeaders = location.proxySetHeaders or {};
    extraConfig = location.extraConfig or "";
  };
  normalizeTls = tls: {
    enable = tls.enable or false;
    protocols = tls.protocols or ["TLSv1.2" "TLSv1.3"];
  };
  normalizeVirtualHost = host: {
    listen = host.listen or [80];
    serverNames = host.serverNames or [];
    root = host.root or "www";
    index = host.index or ["index.html"];
    locations = builtins.mapAttrs (_: normalizeLocation) (host.locations or {});
    tls = normalizeTls (host.tls or {});
    extraConfig = host.extraConfig or "";
  };
  upstreams = builtins.mapAttrs (_: normalizeUpstream) cfg.upstreams;
  virtualHosts = builtins.mapAttrs (_: normalizeVirtualHost) cfg.virtualHosts;
  tlsCredentials = {
    certificate = cfg.tlsCredentials.certificate;
    privateKey = cfg.tlsCredentials.privateKey;
  };

  renderUpstreamServer = server:
    "server ${server.address}"
    + optionalToken (server.weight != null) " weight=${toString server.weight}"
    + optionalToken (server.maxFails != 1) " max_fails=${toString server.maxFails}"
    + optionalToken (server.failTimeout != "10s") " fail_timeout=${server.failTimeout}"
    + optionalToken server.backup " backup"
    + optionalToken server.down " down"
    + ";\n";

  renderUpstream = name: upstream: ''
    upstream ${name} {
    ${indent "  " (builtins.concatStringsSep "" (builtins.map renderUpstreamServer upstream.servers))}${optionalLine (upstream.keepalive != null) "  keepalive ${toString upstream.keepalive};"}${indent "  " upstream.extraConfig}
    }
  '';

  renderLocation = expression: location: let
    handlers = builtins.filter (value: value != null) [location.proxyPass location.root location."return"];
  in
    assert builtins.length handlers <= 1;
      [(literal "    location ${expression} {\n")]
      ++ optionalFragments (location.root != null) [
        (literal "      root ")
        (executionPath (documentPath location.root))
        (literal ";\n")
      ]
      ++ optionalFragments (location.proxyPass != null) [(literal "      proxy_pass ${location.proxyPass};\n")]
      ++ optionalFragments (location."return" != null) [(literal "      return ${toString location."return".code} ${quote location."return".body};\n")]
      ++ optionalFragments (location.tryFiles != []) [(literal "      try_files ${builtins.concatStringsSep " " location.tryFiles};\n")]
      ++ [(literal (builtins.concatStringsSep "" (lib.mapAttrsToList (name: value: "      proxy_set_header ${name} ${quote value};\n") location.proxySetHeaders)))]
      ++ [(literal (indent "      " location.extraConfig))]
      ++ [(literal "    }\n")];

  renderVirtualHost = name: host: let
    tlsListenSuffix =
      if host.tls.enable
      then " ssl"
      else "";
  in
    [(literal "  server {\n")]
    ++ [(literal (builtins.concatStringsSep "" (builtins.map (port: "    listen ${toString port}${tlsListenSuffix};\n") host.listen)))]
    ++ optionalFragments (host.serverNames != []) [(literal "    server_name ${builtins.concatStringsSep " " host.serverNames};\n")]
    ++ [
      (literal "    root ")
      (executionPath (documentPath host.root))
      (literal ";\n")
    ]
    ++ optionalFragments (host.index != []) [(literal "    index ${builtins.concatStringsSep " " host.index};\n")]
    ++ optionalFragments host.tls.enable [
      (literal "    ssl_certificate ")
      (executionPath (resultOf "credential-tls-certificate" "credential-path"))
      (literal ";\n    ssl_certificate_key ")
      (executionPath (resultOf "credential-tls-private-key" "credential-path"))
      (literal ";\n    ssl_protocols ${builtins.concatStringsSep " " host.tls.protocols};\n")
    ]
    ++ lib.concatLists (lib.mapAttrsToList renderLocation host.locations)
    ++ [(literal (indent "    " host.extraConfig))]
    ++ [(literal "  }\n")];

  usesTlsFor = hosts:
    builtins.any (host: (normalizeVirtualHost host).tls.enable) (builtins.attrValues hosts);
  usesTls = usesTlsFor cfg.virtualHosts;
  validUpstreamNames =
    builtins.all
    (name: builtins.match "[A-Za-z0-9_-]+" name != null)
    (builtins.attrNames upstreams);
  validLocationExpressions =
    builtins.all
    (host:
      builtins.all
      (expression: builtins.match "[^{};\n\r]+" expression != null)
      (builtins.attrNames host.locations))
    (builtins.attrValues virtualHosts);
  validHeaderNames =
    builtins.all
    (host:
      builtins.all
      (location:
        builtins.all
        (name: builtins.match "[A-Za-z0-9-]+" name != null)
        (builtins.attrNames location.proxySetHeaders))
      (builtins.attrValues host.locations))
    (builtins.attrValues virtualHosts);
  uniqueListenPorts =
    builtins.all
    (host: builtins.length host.listen == builtins.length (lib.unique host.listen))
    (builtins.attrValues virtualHosts);
  nginxConfigFragments =
    [
      (literal ''
        # Generated by the nginx AOS package configuration module. Do not edit.
        worker_processes ${
          if builtins.isInt cfg.workerProcesses
          then toString cfg.workerProcesses
          else cfg.workerProcesses
        };
        pid
      '')
      (executionPath (pathWithin {
        base = runtimePath;
        relativePath = "nginx.pid";
      }))
      (literal ''
        ;
        error_log stderr notice;

        events {
          worker_connections ${toString cfg.workerConnections};
        }

        http {
          include
      '')
      {
        kind = "artifact-file-path";
        reference = {
          artifact = lib.abilities.packageOutput {};
          path = "share/nginx/mime.types";
        };
      }
      (literal ";\n    default_type application/octet-stream;\n    sendfile on;\n    client_max_body_size ${cfg.clientMaxBodySize};\n    gzip ${
        if cfg.gzip
        then "on"
        else "off"
      };\n    access_log ")
    ]
    ++ (
      if cfg.accessLog
      then [
        (executionPath (pathWithin {
          base = logPath;
          relativePath = "access.log";
        }))
      ]
      else [(literal "off")]
    )
    ++ [(literal ";\n    client_body_temp_path ")]
    ++ builtins.concatMap
    (entry: [
      (executionPath (pathWithin {
        base = statePath;
        relativePath = entry.path;
      }))
      (literal ";\n    ${entry.directive} ")
    ]) [
      {
        path = "client_body";
        directive = "proxy_temp_path";
      }
      {
        path = "proxy";
        directive = "fastcgi_temp_path";
      }
      {
        path = "fastcgi";
        directive = "uwsgi_temp_path";
      }
      {
        path = "uwsgi";
        directive = "scgi_temp_path";
      }
    ]
    ++ [
      (executionPath (pathWithin {
        base = statePath;
        relativePath = "scgi";
      }))
      (literal ";\n\n")
      (literal (indent "    " (builtins.concatStringsSep "" (lib.mapAttrsToList renderUpstream upstreams))))
      (literal (indent "    " cfg.extraHttpConfig))
    ]
    ++ lib.concatLists (lib.mapAttrsToList renderVirtualHost virtualHosts)
    ++ [(literal "}\n")];
  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/nginx";
      inherit arguments;
    };
    ignore_failure = false;
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "nginx";
      inherit key interface parameters;
    };
  storage = serviceManagement.forProducers {
    consumerInstance = "nginx";
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
  runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
    name = "runtime";
    purpose = "runtime";
    mode = "0750";
  };
  configuredCredentials = lib.optionals usesTls [
    {
      name = "tls-certificate";
      reference = tlsCredentials.certificate;
    }
    {
      name = "tls-private-key";
      reference = tlsCredentials.privateKey;
    }
  ];
  credentialRequests = serviceManagement.forCredentialReferences {
    consumerInstance = "nginx";
    references =
      builtins.map (credential: {
        key = "credential-${credential.name}";
        inherit (credential) name reference;
      })
      configuredCredentials;
  };
  configuration = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "nginx";
    declaration = {
      name = "server-configuration";
      source = {
        kind = "interpolated-text";
        fragments = nginxConfigFragments;
        maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
      };
      mode = "0444";
    };
  };
  service = let
    configurationPath = resultOf "server-configuration" "planned-path";
  in {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = ["bind-privileged-network-port"];
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
      security_label = "aos-pkg-nginx";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    consumerInstance = "nginx";
    service = "main";
    lifecycle = {
      description = "nginx HTTP and reverse proxy server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [(command ["-t" "-c" configurationPath])];
      start = [(command ["-c" configurationPath "-g" "daemon off;"])];
      post_start = [];
      stop = [(command ["-c" configurationPath "-s" "quit"])];
      post_stop = [];
      restart = "on-failure";
      restart_token = cfg.restartToken;
      restart_delay_millis = 2000;
      configuration_change_action = "reload";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 60000;
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
    reload = {
      strategy = "command";
      commands = [
        (command ["-t" "-c" configurationPath])
        (command ["-c" configurationPath "-s" "reload"])
      ];
      completion = "command-exit";
    };
    configuration.views = [
      {
        name = "server";
        source = configurationPath;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "runtime";
        source = resultOf "runtime-storage" "planned-path";
        access = "read-write";
      }
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
      ephemeral = true;
      file_creation_mask = "0027";
    };
    isolation = {
      privilege = "unprivileged";
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
      value = 65536;
    };
  };
  producers = [storage runtimeStorage credentialRequests configuration];
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({
      name,
      config,
      ...
    }: let
      serviceUsesTls = usesTlsFor config.virtualHosts;
    in {
      options = lib.optionalAttrs (name == "nginx") {
        enable = lib.mkOption {
          type = abilityTypes.boolean;
          default = false;
          description = "Enable the nginx HTTP and reverse proxy service.";
        };
        workerProcesses = lib.mkOption {
          type = abilityTypes.disjointUnion [positiveInt (abilityTypes.enum ["auto"])];
          default = "auto";
          description = "Number of nginx worker processes, or `auto`.";
        };
        workerConnections = lib.mkOption {
          type = positiveInt;
          default = 1024;
          description = "Maximum simultaneous connections handled by each worker.";
        };
        clientMaxBodySize = lib.mkOption {
          type = size;
          default = "1m";
          description = "Maximum accepted HTTP request body size.";
        };
        gzip = lib.mkOption {
          type = abilityTypes.boolean;
          default = true;
          description = "Enable gzip response compression.";
        };
        accessLog = lib.mkOption {
          type = abilityTypes.boolean;
          default = true;
          description = "Write the HTTP access log to nginx's managed log directory.";
        };
        restartToken = lib.mkOption {
          type = abilityTypes.optional serviceTypes.restartToken;
          default = null;
          description = "Operator-controlled token whose change requests a service restart.";
        };
        upstreams = lib.mkOption {
          type = upstreamMap;
          default = {};
          description = "Named reverse-proxy upstream pools.";
          extensible = true;
        };
        virtualHosts = lib.mkOption {
          type = virtualHostMap;
          default = {};
          description = "Named HTTP virtual hosts.";
          extensible = true;
        };
        extraHttpConfig = lib.mkOption {
          type = confinedDirectives;
          default = "";
          description = "Trusted nginx directives appended to the global HTTP block.";
        };
        tlsCredentials = {
          certificate = lib.mkOption {
            type = credentialReference;
            default = {};
            description = "Opaque reference for the PEM certificate reserved for conditional delivery as `tls-certificate`.";
          };
          privateKey = lib.mkOption {
            type = credentialReference;
            default = {};
            description = "Opaque reference for the PEM private key reserved for conditional delivery as `tls-private-key`.";
          };
        };
      };
      config = lib.optionalAttrs (name == "nginx") {
        credentials =
          if serviceUsesTls
          then {
            views = [
              {
                name = "tls-certificate";
                inherit (config.tlsCredentials.certificate) encrypted;
                reference = resultOf "credential-tls-certificate" "credential-path";
                optional = false;
              }
              {
                name = "tls-private-key";
                inherit (config.tlsCredentials.privateKey) encrypted;
                reference = resultOf "credential-tls-private-key" "credential-path";
                optional = false;
              }
            ];
          }
          else null;
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {
      aos.services.nginx = service;

      assertions = [
        {
          assertion = !cfg.enable || cfg.virtualHosts != {};
          message = "aos.services.nginx.enable requires at least one virtual host";
        }
        {
          assertion =
            !cfg.enable
            || !usesTls
            || serviceManagement.credentialReferenceConfigured tlsCredentials.certificate;
          message = "TLS-enabled nginx virtual hosts require a certificate credential reference";
        }
        {
          assertion =
            !cfg.enable
            || !usesTls
            || serviceManagement.credentialReferenceConfigured tlsCredentials.privateKey;
          message = "TLS-enabled nginx virtual hosts require a private-key credential reference";
        }
        {
          assertion = validUpstreamNames;
          message = "aos.services.nginx.upstreams names may contain only letters, digits, underscores, and hyphens";
        }
        {
          assertion = validLocationExpressions;
          message = "nginx virtual-host location expressions must not contain braces, semicolons, or newlines";
        }
        {
          assertion = validHeaderNames;
          message = "nginx proxy header names may contain only letters, digits, and hyphens";
        }
        {
          assertion = uniqueListenPorts;
          message = "nginx virtual-host listen port lists must not contain duplicates";
        }
      ];
    }
    (serviceManagement.producerModule {
      inherit config lib producers;
      enabled = cfg.enable;
    })
  ];
}
