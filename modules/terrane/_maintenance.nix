##! Explicit GC-to-serving-owner transport resources and deployment checks.
{lib}: let
  types = lib.types;
  bounded = maximum: types.addCheck types.int (value: value > 0 && value <= maximum);
  required = type: description: lib.mkOption {inherit type description;};
  runtimeRoot = "/run/terrane-maintenance";
  socketType = types.strMatching "${runtimeRoot}/[A-Za-z0-9_-]+[.]sock";
in {
  inherit runtimeRoot;

  type = types.submodule {
    options = {
      gcUid = required (types.addCheck types.int (value: value >= 0 && value < 4294967295)) "Explicit GC process UID; must match the deployed dedicated role.";
      maxConnections = required (bounded 1024) "Maximum active maintenance connections per domain.";
      maxRequests = required (bounded 4096) "Maximum successful requests per maintenance connection.";
      connectionTimeoutMs = required (bounded 300000) "Maximum complete connection lifetime in milliseconds.";
      requestTimeoutMs = required (bounded 300000) "Maximum complete GC pass in milliseconds, bounded by the connection lifetime.";
      sockets = required (types.attrsOf socketType) "Explicit domain sockets directly beneath the protected maintenance runtime directory.";
    };
  };

  checks = {
    value,
    domains,
    gcUid,
    hasPublisher,
    serveEnabled,
    roots,
    controlPaths,
  }: let
    enabled = value != null;
    overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;
    paths =
      if enabled
      then builtins.attrValues value.sockets
      else [];
  in [
    {
      assertion = !enabled || (serveEnabled && hasPublisher && value.gcUid == gcUid);
      message = "Terrane maintenance requires the deployed serving owner, publisher identity and dedicated GC UID.";
    }
    {
      assertion =
        !enabled
        || (value.requestTimeoutMs
          <= value.connectionTimeoutMs
          && builtins.length paths > 0
          && builtins.length paths <= 256
          && builtins.attrNames value.sockets == builtins.attrNames domains
          && builtins.all (domain: domain.cache != null && domain.cache.surfaceIndex != null) (builtins.attrValues domains));
      message = "Terrane maintenance requires bounded deadlines and exact coverage of explicitly funded native surface domains.";
    }
    {
      assertion =
        !enabled
        || (builtins.length (lib.unique paths)
          == builtins.length paths
          && builtins.all (path: builtins.stringLength path <= 107) paths
          && builtins.all (path: !overlaps runtimeRoot path) (roots ++ controlPaths));
      message = "Terrane maintenance requires distinct bounded socket names and a runtime directory disjoint from storage and other control endpoints.";
    }
  ];

  render = value:
    if value == null
    then null
    else {
      gc_uid = value.gcUid;
      max_connections = value.maxConnections;
      max_requests = value.maxRequests;
      connection_timeout_ms = value.connectionTimeoutMs;
      request_timeout_ms = value.requestTimeoutMs;
      inherit (value) sockets;
    };
}
