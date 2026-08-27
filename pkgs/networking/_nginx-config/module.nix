##! Typed, composable nginx configuration interface.
##!
##! The package owns the shared `nginx.*` root. Other authenticated packages
##! may contribute named virtual hosts and upstreams, but global policy and
##! service enablement remain operator/owner-only. TLS key material is never
##! accepted as a Nix string. Typed references are projected through optional
##! signed expose declarations only when a TLS virtual host uses them, so an
##! HTTP-only service does not depend on absent credential files.
{
  config,
  lib,
  outputs,
  ...
}: let
  cfg = config.nginx;

  positiveInt = lib.types.addCheck lib.types.int (value: value > 0);
  nonNegativeInt = lib.types.addCheck lib.types.int (value: value >= 0);
  size = lib.types.strMatching "[0-9]+[kKmMgG]?";
  duration = lib.types.strMatching "[0-9]+(ms|s|m|h|d)";
  token = lib.types.strMatching "[^{};[:space:]]+";
  serverName = lib.types.strMatching "[^{};[:space:]]+";
  upstreamAddress = lib.types.strMatching "[^{};[:space:]]+";
  confinedDirectives = lib.types.strMatching "[^{}]*";
  documentRoot = lib.types.strMatching "/var/lib/aos-pkg-nginx/www(/[^\n\r]*)?";
  secretRef = lib.types.submodule ({...}: {
    config._module.strict = true;
    options.ref = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
      default = null;
      description = "Opaque AOS secret reference; secret bytes never enter Nix evaluation.";
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
        description = "Document root in nginx's managed writable state tree.";
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
        type = lib.types.nullOr documentRoot;
        default = null;
        description = "Default document root in nginx's managed writable state tree.";
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
    assert builtins.length handlers <= 1; ''
      location ${expression} {
      ${optionalLine (location.root != null) "  root ${quote location.root};"}${optionalLine (location.proxyPass != null) "  proxy_pass ${location.proxyPass};"}${optionalLine (location."return" != null) "  return ${toString location."return".code} ${quote location."return".body};"}${optionalLine (location.tryFiles != []) "  try_files ${builtins.concatStringsSep " " location.tryFiles};"}${builtins.concatStringsSep "" (lib.mapAttrsToList (name: value: "  proxy_set_header ${name} ${quote value};\n") location.proxySetHeaders)}${indent "  " location.extraConfig}
      }
    '';

  renderVirtualHost = name: host: let
    tlsListenSuffix =
      if host.tls.enable
      then " ssl"
      else "";
  in ''
    server {
    ${builtins.concatStringsSep "" (builtins.map (port: "  listen ${toString port}${tlsListenSuffix};\n") host.listen)}${optionalLine (host.serverNames != []) "  server_name ${builtins.concatStringsSep " " host.serverNames};"}${optionalLine (host.root != null) "  root ${quote host.root};"}${optionalLine (host.index != []) "  index ${builtins.concatStringsSep " " host.index};"}${optionalLine host.tls.enable "  ssl_certificate /run/credentials/nginx.service/tls-certificate;"}${optionalLine host.tls.enable "  ssl_certificate_key /run/credentials/nginx.service/tls-private-key;"}${optionalLine host.tls.enable "  ssl_protocols ${builtins.concatStringsSep " " host.tls.protocols};"}${builtins.concatStringsSep "" (lib.mapAttrsToList renderLocation host.locations)}${indent "  " host.extraConfig}
    }
  '';

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
  nginxConfig = ''
    # Generated by the nginx AOS package configuration module. Do not edit.
    worker_processes ${
      if builtins.isInt cfg.workerProcesses
      then toString cfg.workerProcesses
      else cfg.workerProcesses
    };
    pid /run/nginx/nginx.pid;
    error_log stderr notice;

    events {
      worker_connections ${toString cfg.workerConnections};
    }

    http {
      include ${outputs.self}/share/nginx/mime.types;
      default_type application/octet-stream;
      sendfile on;
      client_max_body_size ${cfg.clientMaxBodySize};
      gzip ${
      if cfg.gzip
      then "on"
      else "off"
    };
      access_log ${
      if cfg.accessLog
      then "/dev/stdout"
      else "off"
    };
      client_body_temp_path /var/lib/aos-pkg-nginx/client_body;
      proxy_temp_path /var/lib/aos-pkg-nginx/proxy;
      fastcgi_temp_path /var/lib/aos-pkg-nginx/fastcgi;
      uwsgi_temp_path /var/lib/aos-pkg-nginx/uwsgi;
      scgi_temp_path /var/lib/aos-pkg-nginx/scgi;

    ${indent "  " (builtins.concatStringsSep "" (lib.mapAttrsToList renderUpstream cfg.upstreams))}
    ${indent "  " cfg.extraHttpConfig}
    ${indent "  " (builtins.concatStringsSep "" (lib.mapAttrsToList renderVirtualHost cfg.virtualHosts))}
    }
  '';
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
      description = "Write the HTTP access log to the service journal.";
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

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.virtualHosts != {};
        message = "nginx.enable requires at least one nginx.virtualHosts entry";
      }
      {
        assertion = !usesTls || cfg.tlsCredentials.certificate.ref != null;
        message = "TLS-enabled nginx virtual hosts require nginx.tlsCredentials.certificate.ref";
      }
      {
        assertion = !usesTls || cfg.tlsCredentials.privateKey.ref != null;
        message = "TLS-enabled nginx virtual hosts require nginx.tlsCredentials.privateKey.ref";
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

    nginx.config.runtime = {
      enabled = cfg.enable;
      # The signed generic artifact renderer observes this digest and invokes
      # reload-or-restart for nginx.service after the new `/etc` generation is
      # live. Unit-byte changes still restart, so a package upgrade never tries
      # to reload an old master through a new payload root.
      generation = builtins.hashString "sha256" nginxConfig;
    };

    nginx.credentials = lib.optionalAttrs usesTls {
      "tls-certificate".ref = cfg.tlsCredentials.certificate.ref;
      "tls-private-key".ref = cfg.tlsCredentials.privateKey.ref;
    };

    environment.etc."nginx/nginx.conf" = {
      text = nginxConfig;
      mode = "0444";
    };
  };
}
