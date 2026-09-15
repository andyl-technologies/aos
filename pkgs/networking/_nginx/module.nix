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
  cfg = config.nginx;

  inherit (lib.serviceTypes) positiveInt nonNegativeInt;
  inherit (lib.abilities) pathWithin resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;
  size = lib.types.strMatching "[0-9]+[kKmMgG]?";
  duration = lib.types.strMatching "[0-9]+(ms|s|m|h|d)";
  token = lib.types.strMatching "[^{};[:space:]]+";
  serverName = lib.types.strMatching "[^{};[:space:]]+";
  upstreamAddress = lib.types.strMatching "[^{};[:space:]]+";
  confinedDirectives = lib.types.strMatching "[^{}]*";
  documentRoot = abilityTypes.relativePath;
  secretRef = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      resource = lib.mkOption {
        type = abilityTypes.optional (abilityTypes.deferredResult abilityTypes.resourceReference);
        default = null;
        description = "Typed source resource for this delivered credential.";
      };
      encrypted = lib.mkOption {
        type = abilityTypes.boolean;
        default = false;
        description = "Whether the credential requires encrypted delivery.";
      };
    };
  });

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
  runtimePath = resultOf "runtime-storage" "storage-path";
  statePath = resultOf "state-storage" "storage-path";
  logPath = resultOf "log-storage" "storage-path";
  documentPath = relativePath:
    pathWithin {
      base = statePath;
      inherit relativePath;
    };

  upstreamServerType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      address = lib.mkOption {
        type = upstreamAddress;
        description = "Host, address, or unix socket accepted by nginx's upstream server directive.";
      };
      weight = lib.mkOption {
        type = lib.types.nullOr positiveInt;
        default = null;
        description = "Relative upstream selection weight.";
      };
      maxFails = lib.mkOption {
        type = nonNegativeInt;
        default = 1;
        description = "Failures allowed during failTimeout before the server is considered unavailable.";
      };
      failTimeout = lib.mkOption {
        type = duration;
        default = "10s";
        description = "Failure accounting and temporary-unavailability interval.";
      };
      backup = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Use this server only when primary upstreams are unavailable.";
      };
      down = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Administratively disable this upstream server.";
      };
    };
  });

  upstreamType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      servers = lib.mkOption {
        type = lib.types.listOf upstreamServerType;
        default = [];
        description = "Ordered upstream server pool.";
      };
      keepalive = lib.mkOption {
        type = lib.types.nullOr positiveInt;
        default = null;
        description = "Maximum idle keepalive connections retained per worker.";
      };
      extraConfig = lib.mkOption {
        type = confinedDirectives;
        default = "";
        description = "Nginx directives appended inside this upstream block; braces are forbidden.";
      };
    };
  });

  returnType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      code = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value >= 100 && value <= 599);
        description = "HTTP response or redirect status code.";
      };
      body = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Literal response body or redirect URI.";
      };
    };
  });

  locationType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      proxyPass = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "[A-Za-z][A-Za-z0-9+.-]*://[^;[:space:]]+");
        default = null;
        description = "Upstream URI passed to proxy_pass.";
      };
      root = lib.mkOption {
        type = lib.types.nullOr documentRoot;
        default = null;
        description = "Relative document root within nginx's managed state storage.";
      };
      "return" = lib.mkOption {
        type = lib.types.nullOr returnType;
        default = null;
        description = "Immediate HTTP response or redirect.";
      };
      tryFiles = lib.mkOption {
        type = lib.types.listOf token;
        default = [];
        description = "Candidate paths passed to nginx's try_files directive.";
      };
      proxySetHeaders = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = {};
        description = "Request headers set before proxying.";
      };
      extraConfig = lib.mkOption {
        type = confinedDirectives;
        default = "";
        description = "Nginx directives appended inside this location block; braces are forbidden.";
      };
    };
  });

  tlsType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable TLS using nginx's opaque certificate and private-key credentials.";
      };
      protocols = lib.mkOption {
        type = lib.types.listOf (lib.types.enum ["TLSv1.2" "TLSv1.3"]);
        default = ["TLSv1.2" "TLSv1.3"];
        description = "Allowed TLS protocol versions.";
      };
    };
  });

  virtualHostType = lib.types.submodule ({...}: {
    config._module.strict = true;
    options = {
      listen = lib.mkOption {
        type = lib.types.listOf lib.types.port;
        default = [80];
        description = "TCP ports on which this virtual host listens.";
      };
      serverNames = lib.mkOption {
        type = lib.types.listOf serverName;
        default = [];
        description = "Host names matched by this virtual host.";
      };
      root = lib.mkOption {
        type = documentRoot;
        default = "www";
        description = "Relative document root within nginx's managed state storage.";
      };
      index = lib.mkOption {
        type = lib.types.listOf token;
        default = ["index.html"];
        description = "Default index file names.";
      };
      locations = lib.mkOption {
        type = lib.types.attrsOf locationType;
        default = {};
        description = "Locations keyed by an nginx location expression.";
        contributable = true;
      };
      tls = lib.mkOption {
        type = tlsType;
        default = {};
        description = "TLS policy for this virtual host.";
      };
      extraConfig = lib.mkOption {
        type = confinedDirectives;
        default = "";
        description = "Nginx directives appended inside this server block; braces are forbidden.";
      };
    };
  });

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

  usesTls = builtins.any (host: host.tls.enable) (builtins.attrValues cfg.virtualHosts);
  validUpstreamNames =
    builtins.all
    (name: builtins.match "[A-Za-z0-9_-]+" name != null)
    (builtins.attrNames cfg.upstreams);
  validLocationExpressions =
    builtins.all
    (host:
      builtins.all
      (expression: builtins.match "[^{};\n\r]+" expression != null)
      (builtins.attrNames host.locations))
    (builtins.attrValues cfg.virtualHosts);
  validHeaderNames =
    builtins.all
    (host:
      builtins.all
      (location:
        builtins.all
        (name: builtins.match "[A-Za-z0-9-]+" name != null)
        (builtins.attrNames location.proxySetHeaders))
      (builtins.attrValues host.locations))
    (builtins.attrValues cfg.virtualHosts);
  uniqueListenPorts =
    builtins.all
    (host: builtins.length host.listen == builtins.length (lib.unique host.listen))
    (builtins.attrValues cfg.virtualHosts);
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
      (literal (indent "    " (builtins.concatStringsSep "" (lib.mapAttrsToList renderUpstream cfg.upstreams))))
      (literal (indent "    " cfg.extraHttpConfig))
    ]
    ++ lib.concatLists (lib.mapAttrsToList renderVirtualHost cfg.virtualHosts)
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
      inherit (cfg.tlsCredentials.certificate) resource encrypted;
    }
    {
      name = "tls-private-key";
      inherit (cfg.tlsCredentials.privateKey) resource encrypted;
    }
  ];
  credentialRequests = serviceManagement.forProducers {
    consumerInstance = "nginx";
    interface = serviceManagement.interfaces.credentialDelivery;
    producers =
      builtins.map (credential: {
        key = "credential-${credential.name}";
        parameters = {
          inherit (credential) name encrypted;
          source = credential.resource;
        };
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
  serviceFor = withCredentials: let
    configurationPath = resultOf "server-configuration" "execution-path";
    credentials =
      if withCredentials
      then {
        views = [
          {
            name = "tls-certificate";
            inherit (cfg.tlsCredentials.certificate) encrypted;
            reference = resultOf "credential-tls-certificate" "credential-path";
            optional = false;
          }
          {
            name = "tls-private-key";
            inherit (cfg.tlsCredentials.privateKey) encrypted;
            reference = resultOf "credential-tls-private-key" "credential-path";
            optional = false;
          }
        ];
      }
      else null;
  in
    serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "nginx";
      declaration = {
        service = "main";
        enabled = true;
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
        inherit credentials;
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
        linux_isolation = {
          allow_privilege_escalation = false;
          ambient_capabilities = ["CAP_NET_BIND_SERVICE"];
          capability_bounds = {
            kind = "restricted";
            capabilities = ["CAP_NET_BIND_SERVICE"];
          };
          control_group_delegation = false;
          control_group_access = "read-only";
          device_namespace = "shared";
          kernel_clock_mutation = false;
          kernel_hostname_mutation = false;
          kernel_log_access = false;
          kernel_module_access = false;
          kernel_tunable_access = false;
          lock_personality = true;
          memory_write_execute = false;
          namespace_isolation = [];
          network_address_families = ["ipv4" "ipv6" "unix"];
          oom_score_adjust = 0;
          permit_realtime = false;
          permit_suid_sgid = false;
          process_visibility = "all";
          security_label = "aos-pkg-nginx";
          syscall_architectures = [];
          syscall_allow = [];
          syscall_deny = [];
          syscall_profile = "system-service";
          user_namespace_ownership = "none";
        };
      };
    };
  configuredService = serviceFor usesTls;
  potentialAbilityFragments = [
    storage
    runtimeStorage
    credentialRequests
    configuration
    (serviceFor true)
  ];
  configuredAbilityFragments = [storage runtimeStorage credentialRequests configuration configuredService];
in {
  options.nginx = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the nginx HTTP and reverse proxy service.";
    };
    workerProcesses = lib.mkOption {
      type = lib.types.either positiveInt (lib.types.enum ["auto"]);
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
      type = lib.types.bool;
      default = true;
      description = "Enable gzip response compression.";
    };
    accessLog = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Write the HTTP access log to nginx's managed log directory.";
    };
    restartToken = lib.mkOption {
      type = lib.types.nullOr serviceTypes.restartToken;
      default = null;
      description = "Operator-controlled token whose change requests a service restart.";
    };
    upstreams = lib.mkOption {
      type = lib.types.attrsOf upstreamType;
      default = {};
      description = "Named reverse-proxy upstream pools.";
      contributable = true;
    };
    virtualHosts = lib.mkOption {
      type = lib.types.attrsOf virtualHostType;
      default = {};
      description = "Named HTTP virtual hosts.";
      contributable = true;
    };
    extraHttpConfig = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Trusted nginx directives appended to the global HTTP block.";
    };
    tlsCredentials = {
      certificate = lib.mkOption {
        type = secretRef;
        default = {};
        description = "Opaque reference for the PEM certificate reserved for conditional delivery as `tls-certificate`.";
      };
      privateKey = lib.mkOption {
        type = secretRef;
        default = {};
        description = "Opaque reference for the PEM private key reserved for conditional delivery as `tls-private-key`.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (builtins.map
        (fragment: (serviceManagement.splitContribution fragment).declarations)
        potentialAbilityFragments);

      assertions = [
        {
          assertion = !cfg.enable || cfg.virtualHosts != {};
          message = "nginx.enable requires at least one nginx.virtualHosts entry";
        }
        {
          assertion = !cfg.enable || !usesTls || cfg.tlsCredentials.certificate.resource != null;
          message = "TLS-enabled nginx virtual hosts require nginx.tlsCredentials.certificate.resource";
        }
        {
          assertion = !cfg.enable || !usesTls || cfg.tlsCredentials.privateKey.resource != null;
          message = "TLS-enabled nginx virtual hosts require nginx.tlsCredentials.privateKey.resource";
        }
        {
          assertion = validUpstreamNames;
          message = "nginx.upstreams names may contain only letters, digits, underscores, and hyphens";
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
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.nginx = {};}]
        ++ builtins.map
        (fragment: (serviceManagement.splitContribution fragment).configured)
        configuredAbilityFragments
      );
    })
  ];
}
