##! Exercises maintenance configuration, transport custody and role isolation.
{
  lib,
  evaluate,
  nativeFixture,
  cacheFixture,
  surfaceIndexFixture,
  checksPass,
}: let
  settings = {
    gcUid = 843;
    maxConnections = 2;
    maxRequests = 1;
    connectionTimeoutMs = 3000;
    requestTimeoutMs = 2000;
    sockets.public = "/run/terrane-maintenance/public.sock";
  };
  fixture = lib.recursiveUpdate nativeFixture {
    aos.terrane.hostTier = {
      maintenance = settings;
      domains.public.cache = cacheFixture // {surfaceIndex = surfaceIndexFixture;};
    };
  };
  configured = extra: evaluate (lib.recursiveUpdate fixture extra);
  accepted = extra: let
    cfg = configured extra;
    result = builtins.tryEval (builtins.deepSeq cfg.environment.etc."terrane/terrane.toml".text (checksPass cfg));
  in
    result.success && result.value;
  rejected = extra: !accepted extra;
  cfg = configured {};
  text = cfg.environment.etc."terrane/terrane.toml".text;
  serve = cfg.systemd.services.terrane-serve;
  gc = cfg.systemd.services.terrane-gc;
in [
  {
    name = "maintenance-explicit-schema";
    pass =
      checksPass cfg
      && builtins.all (field: lib.hasInfix field text) ["[host_tier.maintenance]" "gc_uid = 843" "max_connections = 2" "max_requests = 1" "connection_timeout_ms = 3000" "request_timeout_ms = 2000" "[host_tier.maintenance.sockets]" "public = \"/run/terrane-maintenance/public.sock\""]
      && !(lib.hasInfix "connectionTimeoutMs" text);
  }
  {
    name = "maintenance-gc-excludes-private-state-groups-and-writes";
    pass =
      gc.serviceConfig.SupplementaryGroups
      == ["terrane-maintenance"]
      && cfg.aos.users.users.terrane-gc.extraGroups == ["terrane-maintenance"]
      && gc.serviceConfig.ReadWritePaths == []
      && cfg.aos.users.groups.terrane-maintenance.gid == 846
      && serve.serviceConfig.SupplementaryGroups == ["terrane-cache" "terrane-content"];
  }
  {
    name = "maintenance-protected-parent-and-serving-dependency";
    pass =
      lib.hasInfix "d /run/terrane-maintenance 2750 terrane terrane-maintenance - -" cfg.environment.etc."tmpfiles.d/terrane.conf".text
      && builtins.elem "/run/terrane-maintenance" serve.serviceConfig.ReadWritePaths
      && serve.serviceConfig.Type == "notify"
      && serve.serviceConfig.NotifyAccess == "main"
      && builtins.elem "terrane-serve.service" gc.after
      && builtins.elem "terrane-serve.service" gc.requires;
  }
  {
    name = "maintenance-bounds-and-required-inputs-refused";
    pass = builtins.all (maintenance: rejected {aos.terrane.hostTier.maintenance = lib.mkForce maintenance;}) [
      (builtins.removeAttrs settings ["maxRequests"])
      (settings // {gcUid = 840;})
      (settings // {maxConnections = 0;})
      (settings // {maxConnections = 1025;})
      (settings // {maxRequests = 4097;})
      (settings // {connectionTimeoutMs = 300001;})
      (settings // {requestTimeoutMs = 3001;})
      (settings // {sockets = {};})
      (settings // {sockets = {public = "/run/terrane-maintenance/../public.sock";};})
      (settings // {sockets = {public = "/var/lib/terrane/control.sock";};})
    ];
  }
  {
    name = "maintenance-owner-funding-and-domain-coverage-refused";
    pass = builtins.all rejected [
      {aos.terrane.roles.serve.enable = false;}
      {aos.terrane.hostTier.publisher = null;}
      {aos.terrane.hostTier.domains.public.cache.surfaceIndex = null;}
      {aos.terrane.hostTier.maintenance.sockets.foreign = "/run/terrane-maintenance/foreign.sock";}
      {aos.terrane.hostTier.path = "/run/terrane-maintenance";}
      {aos.terrane.hostTier.quota.socketPath = "/run/terrane-maintenance/quota.sock";}
    ];
  }
  {
    name = "maintenance-domain-sockets-unique";
    pass = rejected {
      aos.terrane.hostTier = {
        domains."private:example" = {
          path = "/var/lib/terrane-private";
          wipe = "none";
          publisher = nativeFixture.aos.terrane.hostTier.domains.public.publisher;
          cache = cacheFixture // {surfaceIndex = surfaceIndexFixture;};
        };
        maintenance.sockets."private:example" = settings.sockets.public;
      };
    };
  }
  {
    name = "maintenance-transport-group-cannot-be-aliased-or-granted";
    pass = builtins.all rejected [
      {aos.users.groups.unrelated.gid = 846;}
      {
        aos.users.users.unrelated = {
          uid = 900;
          group = "terrane-maintenance";
        };
      }
      {
        aos.users.users.unrelated = {
          uid = 900;
          extraGroups = ["terrane-maintenance"];
        };
      }
      {aos.users.groups.terrane-maintenance.members = ["terrane-publish"];}
      {systemd.services.terrane-gc.serviceConfig.SupplementaryGroups = lib.mkForce ["terrane-cache" "terrane-maintenance"];}
    ];
  }
]
