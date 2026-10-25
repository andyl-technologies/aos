##! Terrane host options, single TOML configuration, and isolated roles (PKG-8/10).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.terrane;
  types = lib.types;
  toml = lib.formats.toml {inherit lib pkgs;};
  localRepository = import ./_local-repository.nix {inherit lib;};
  nativeCache = import ./_cache.nix {inherit lib;};
  maintenance = import ./_maintenance.nix {inherit lib;};
  sdkOutput = import ./_sdk-output.nix {inherit lib;};
  maintenanceEnabled = cfg.hostTier.maintenance != null;
  # Reject traversal and unit-file metacharacters before paths reach tmpfiles
  # or systemd. Parent ownership is part of the publisher's security boundary.
  pathType = types.strMatching "/[A-Za-z0-9_./-]+";
  cleanPath = path: path != "/" && builtins.all (part: part != ".." && part != "." && part != "") (builtins.tail (lib.splitString "/" path));
  referenceType = types.strMatching "(file:/[^[:space:]]+|secret:[^[:space:]]+|anonymous:[^[:space:]]+)";
  option = type: default: description: lib.mkOption {inherit type default description;};
  positive = types.addCheck types.int (value: value > 0);
  uidType = types.addCheck types.int (value: value >= 0 && value < 4294967295);
  ownerIdType = types.addCheck types.str (value: builtins.stringLength value > 0 && builtins.stringLength value <= 256);
  publisherType = types.submodule {
    options = {
      socketPath = lib.mkOption {
        type = pathType;
        description = "Absolute publisher transport socket path.";
      };
      serveUid = lib.mkOption {
        type = uidType;
        description = "Authorized serve process UID.";
      };
      publishUid = lib.mkOption {
        type = uidType;
        description = "Publisher process UID.";
      };
      contentUid = lib.mkOption {
        type = uidType;
        description = "Cache content directory owner UID.";
      };
      contentGid = lib.mkOption {
        type = uidType;
        description = "Cache content directory group ID.";
      };
      maxConnections = lib.mkOption {
        type = types.addCheck positive (value: value <= 1024);
        description = "Maximum simultaneous publisher connections, up to 1024.";
      };
    };
  };
  domainPublisherType = types.submodule {
    options = {
      retirementGraceMs = lib.mkOption {
        type = types.addCheck positive (value: value <= 300000);
        description = "Explicit retirement grace in milliseconds, up to 300000.";
      };
      chunkProfile = lib.mkOption {
        type = types.enum ["cdc-1m"];
        description = "Explicit registered chunk profile.";
      };
      chunkSeed = lib.mkOption {
        type = types.strMatching "[0-9a-f]{64}";
        description = "Explicit lowercase hexadecimal chunk-profile seed.";
      };
    };
  };
  quotaType = types.submodule {
    options = {
      socketPath = lib.mkOption {
        type = pathType;
        description = "Absolute host quota inspector socket path.";
      };
      configurationEpoch = lib.mkOption {
        type = types.strMatching "[0-9a-f]{32}";
        description = "Explicit lowercase hexadecimal host provisioning epoch.";
      };
    };
  };
  domainType = types.submodule {
    options = {
      path = lib.mkOption {
        type = pathType;
        description = "Absolute filesystem root for this disclosure domain.";
      };
      cache = option (types.nullOr nativeCache.type) null "Explicit finite native cache resources; omission leaves cache startup unavailable.";
      publisher = option (types.nullOr domainPublisherType) null "Explicit native publisher profile for this domain; omission supplies no defaults.";
      administrativeRoot = option (types.nullOr pathType) null "Explicit protected administrative allocation root belonging only to this domain.";
      quotaOwnerId = option (types.nullOr ownerIdType) null "Explicit host allocation owner identifier.";
      wipe = option (types.nullOr (types.enum ["none" "zero"])) null "Wipe policy; unset defaults to zero for private domains and none otherwise (DOM-18). Sealed host tiers reject zero, including the private-domain default (D-128).";
    };
  };
  exposureType = types.submodule {
    options = {
      id = lib.mkOption {
        type = types.str;
        description = "Unique exposure identifier.";
      };
      view = lib.mkOption {
        type = types.str;
        description = "Terrane view selector.";
      };
      surface = lib.mkOption {
        type = types.str;
        description = "Registered surface name, validated by Terrane.";
      };
      at = lib.mkOption {
        type = types.str;
        description = "Endpoint interpreted by the selected surface.";
      };
      token = lib.mkOption {
        type = referenceType;
        description = "Credential reference or anonymous grant; never an inline credential.";
      };
      mode = option (types.submodule {
        options = {
          reader = option (types.nullOr (types.enum ["pinned" "follow"])) null "Reader mode; omitted to retain selector-dependent defaults.";
          writer = option (types.nullOr (types.enum ["manual" "periodic" "sync"])) null "Writer mode when supported by the surface.";
        };
      }) {} "Exposure consistency modes.";
      options = option (types.attrsOf toml.type) {} "Structured surface options validated by the runtime schema.";
    };
  };
  roleNames = ["serve" "publish" "realize" "gc"];
  identities = {
    serve = 840;
    publish = 841;
    realize = 842;
    gc = 843;
  };
  userFor = role:
    if role == "serve"
    then "terrane"
    else "terrane-${role}";
  # The publisher can retire cache bodies but cannot modify pins or quotas.
  groupsFor = role:
    if role == "gc" && maintenanceEnabled
    then ["terrane-maintenance"]
    else
      lib.optional (role == "serve" || role == "gc") "terrane-cache"
      ++ lib.optional (role == "serve" || role == "gc" || role == "publish") "terrane-content";
  reservedGroupIds =
    identities
    // {
      cache = 844;
      content = 845;
      maintenance = 846;
    };
  expectedGroupName = name:
    if name == "cache"
    then "terrane-cache"
    else if name == "content"
    then "terrane-content"
    else if name == "maintenance"
    then "terrane-maintenance"
    else userFor name;
  publicRoot = (cfg.hostTier.domains.public or {path = cfg.hostTier.path;}).path;
  domainRoots =
    [
      {
        domain = "public";
        path = publicRoot;
      }
    ]
    ++ lib.mapAttrsToList (domain: value: {
      inherit domain;
      inherit (value) path;
    }) (builtins.removeAttrs cfg.hostTier.domains ["public"]);
  roots = map (entry: entry.path) domainRoots;
  declaredRoots = lib.unique ([cfg.hostTier.path] ++ roots);
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;
  uniqueRoots = builtins.all (a: builtins.all (b: a == b || !overlaps a b) roots) roots && builtins.length (lib.unique roots) == builtins.length roots;
  writable = role:
    if role == "gc" && maintenanceEnabled
    then []
    else if role == "publish"
    then ["/run/terrane-publish"] ++ builtins.concatMap (root: ["${root}/sealed" "${root}/staging" "${root}/pending-delete" "${root}/state/publication" "${root}/chunks" "${root}/objects" "${root}/quarantine"]) roots
    else if role == "serve" || role == "gc"
    then
      builtins.concatMap (root: ["${root}/state/cache" "${root}/chunks" "${root}/objects" "${root}/quarantine"]) roots
      ++ lib.optionals (role == "serve") cfg.sdkOutputRoots
      ++ lib.optional (role == "serve" && maintenanceEnabled) maintenance.runtimeRoot
    else [];
  # Preserve DOM-18 defaults so an unsupported private policy fails closed.
  effectiveWipe = name: domain:
    if domain.wipe != null
    then domain.wipe
    else if lib.hasPrefix "private:" name
    then "zero"
    else "none";

  configuration = {
    store = cfg.store;
    local_repository = localRepository.render cfg.localRepository;
    locality = {inherit (cfg.locality) region zone host;};
    host_tier = {
      path = cfg.hostTier.path;
      size_bytes = cfg.hostTier.sizeBytes;
      reassembly = cfg.hostTier.reassembly;
      maintenance = maintenance.render cfg.hostTier.maintenance;
      publisher =
        if cfg.hostTier.publisher == null
        then null
        else {
          socket_path = cfg.hostTier.publisher.socketPath;
          serve_uid = cfg.hostTier.publisher.serveUid;
          publish_uid = cfg.hostTier.publisher.publishUid;
          content_uid = cfg.hostTier.publisher.contentUid;
          content_gid = cfg.hostTier.publisher.contentGid;
          max_connections = cfg.hostTier.publisher.maxConnections;
        };
      quota =
        if cfg.hostTier.quota == null
        then null
        else {
          socket_path = cfg.hostTier.quota.socketPath;
          configuration_epoch = cfg.hostTier.quota.configurationEpoch;
        };
      domains =
        lib.mapAttrs (name: domain: {
          inherit (domain) path;
          cache = nativeCache.render domain.cache;
          quota_owner_id = domain.quotaOwnerId;
          administrative_root =
            if domain.administrativeRoot != null
            then domain.administrativeRoot
            else if name == "public" && domain.path != cfg.hostTier.path
            then cfg.hostTier.path
            else null;
          publisher =
            if domain.publisher == null
            then null
            else {
              retirement_grace_ms = domain.publisher.retirementGraceMs;
              chunk_profile = domain.publisher.chunkProfile;
              chunk_seed = domain.publisher.chunkSeed;
            };
          wipe = effectiveWipe name domain;
        })
        cfg.hostTier.domains;
    };
    tokens = {
      issuer_public_keys = cfg.tokens.issuerPublicKeys;
      host_token = cfg.tokens.hostToken;
    };
    expose =
      map (exposure: {
        inherit (exposure) id view surface at token options;
        mode = {inherit (exposure.mode) reader writer;};
      })
      cfg.exposures;
  };
  service = role: {
    description = "Terrane ${role} role";
    wantedBy = lib.optional (role != "gc") "multi-user.target";
    after = ["systemd-tmpfiles-setup.service"] ++ lib.optional (cfg.hostHelper.enable && role != "realize") "aos-terrane-host-quota.service" ++ lib.optional (role == "gc" && maintenanceEnabled) "terrane-serve.service";
    requires = ["systemd-tmpfiles-setup.service"] ++ lib.optional (cfg.hostHelper.enable && role != "realize") "aos-terrane-host-quota.service" ++ lib.optional (role == "gc" && maintenanceEnabled) "terrane-serve.service";
    serviceConfig = {
      Type =
        if role == "gc"
        then "oneshot"
        else if role == "serve" && maintenanceEnabled
        then "notify"
        else "simple";
      NotifyAccess = "main";
      ExecStart = "${cfg.package}/bin/terrane --config /etc/terrane/terrane.toml --role ${role}";
      User = userFor role;
      Group = userFor role;
      SupplementaryGroups = groupsFor role;
      DynamicUser = false;
      Slice =
        if role == "serve"
        then "aos-control.slice"
        else "aos-view-services.slice";
      UMask =
        if role == "serve" || role == "gc"
        then "0007"
        else "0077";
      NoNewPrivileges = true;
      CapabilityBoundingSet = "";
      AmbientCapabilities = "";
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      PrivateUsers = false;
      PrivateNetwork = role == "publish" || role == "realize";
      RestrictAddressFamilies =
        if role == "publish" || role == "realize"
        then "AF_UNIX"
        else "AF_UNIX AF_INET AF_INET6";
      RestrictNamespaces = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectProc = "invisible";
      ProcSubset = "pid";
      RestrictSUIDSGID = true;
      LockPersonality = true;
      ReadWritePaths = writable role;
      # The optional prefix preserves SDK-only startup before host quota
      # provisioning. Existing global project claims are never role data.
      InaccessiblePaths = ["-/var/lib/terrane-host/project-claims"];
      # Native startup compares O_PATH identities with the quota helper's actual
      # roots. Inaccessible mounts replace those inodes. Preserve them through
      # read-only binds; publisher-owned mode 0700 still denies directory reads.
      ReadOnlyPaths = lib.optionals (role != "publish") (builtins.concatMap (root: ["${root}/sealed" "${root}/staging" "${root}/pending-delete" "${root}/state/publication"]) roots);
    };
  };
in {
  imports = [./_host-quota.nix];

  options.aos.terrane = {
    enable = lib.mkEnableOption "the Terrane host tier";
    package = option types.package pkgs.terrane "AOS-built Terrane program.";
    localRepository = option (types.nullOr localRepository.type) null "Explicit trust inputs for serve-only reopening of an existing leaf file:// bucket. This does not configure host-cache routing or create authority.";
    store = lib.mkOption {
      type = types.str;
      description = "Store expression using the Terrane specification grammar.";
    };
    locality = option (types.submodule {
      options = builtins.listToAttrs (map (name: {
        inherit name;
        value = option types.str "" "Store ${name} locality label.";
      }) ["region" "zone" "host"]);
    }) {} "Store locality labels.";
    hostTier = {
      maintenance = option (types.nullOr maintenance.type) null "Explicit bounded reconciliation against original serving owners; grants GC no direct cache-state access.";
      publisher = option (types.nullOr publisherType) null "Explicit publisher transport and process identities; omitted for SDK-only operation.";
      quota = option (types.nullOr quotaType) null "Explicit host quota inspector binding; an external helper is not enabled automatically.";
      path = option pathType "/var/lib/terrane" "Absolute host-tier root.";
      sizeBytes = lib.mkOption {
        type = types.addCheck types.int (value: value > 0);
        description = "Maximum host-tier bytes; capacity must be explicit.";
      };
      reassembly = option (types.enum ["never" "always"]) "never" "T2 object reassembly policy.";
      domains = option (types.attrsOf domainType) {} "Domain-specific roots; separate filesystems must be provisioned by the operator when isolation requires them.";
    };
    sdkOutputRoots = option sdkOutput.type [] "Existing dedicated SDK snapshot containers writable by Serve. Provision ownership separately; each SDK endpoint must be a new directory strictly beneath one container. No directories are created or chowned by this option.";
    exposures = option (types.listOf exposureType) [] "Ordered exposures; runtime validation accepts or rejects the complete configuration.";
    tokens = {
      issuerPublicKeys = option (types.listOf (types.strMatching "file:/[^[:space:]]+")) [] "References to issuer public-key files.";
      hostToken = option (types.nullOr referenceType) null "Host credential reference; no secret bytes enter the Nix store.";
    };
    roles = builtins.listToAttrs (map (name: {
        inherit name;
        value.enable = option types.bool true "Run the ${name} role.";
      })
      roleNames);
    gc.interval = option types.str "hourly" "Systemd calendar expression for host-local collection.";
  };

  config = lib.mkIf cfg.enable {
    assertions =
      (localRepository.checks {
        value = cfg.localRepository;
        serveEnabled = cfg.roles.serve.enable;
        serveUid = identities.serve;
      })
      ++ (sdkOutput.checks {
        outputRoots = cfg.sdkOutputRoots;
        inherit (cfg) exposures store localRepository;
        protectedPaths =
          declaredRoots
          ++ builtins.filter (root: root != null) (map (domain: domain.administrativeRoot) (builtins.attrValues cfg.hostTier.domains))
          ++ ["/var/lib/terrane-host/project-claims" maintenance.runtimeRoot "/run/terrane-publish" "/run/aos-terrane-host"]
          ++ lib.optional (cfg.hostTier.quota != null) cfg.hostTier.quota.socketPath
          ++ map (reference: lib.removePrefix "file:" reference) (builtins.filter (lib.hasPrefix "file:")
            (cfg.tokens.issuerPublicKeys ++ lib.optional (cfg.tokens.hostToken != null) cfg.tokens.hostToken ++ map (exposure: exposure.token) cfg.exposures));
      })
      ++ (import ./_identity-checks.nix {
        inherit config roleNames identities userFor groupsFor reservedGroupIds expectedGroupName;
      })
      ++ (nativeCache.checks {
        domains = cfg.hostTier.domains;
        tierBudget = cfg.hostTier.sizeBytes;
        hasPublisher = cfg.hostTier.publisher != null;
        hasQuota = cfg.hostTier.quota != null;
      })
      ++ (maintenance.checks {
        value = cfg.hostTier.maintenance;
        domains = cfg.hostTier.domains;
        gcUid = identities.gc;
        hasPublisher = cfg.hostTier.publisher != null;
        serveEnabled = cfg.roles.serve.enable;
        roots = declaredRoots ++ builtins.filter (root: root != null) (map (domain: domain.administrativeRoot) (builtins.attrValues cfg.hostTier.domains));
        controlPaths = lib.optional (cfg.hostTier.publisher != null) cfg.hostTier.publisher.socketPath ++ lib.optional (cfg.hostTier.quota != null) cfg.hostTier.quota.socketPath;
      })
      ++ [
        {
          assertion = builtins.all (root: !overlaps root "/var/lib/terrane-host/project-claims") declaredRoots;
          message = "Terrane content and administrative roots must stay disjoint from the fixed host-global project registry.";
        }
        {
          assertion = cfg.hostTier.publisher == null || (cfg.hostTier.publisher.socketPath == "/run/terrane-publish/publisher.sock" && cfg.hostTier.publisher.serveUid == identities.serve && cfg.hostTier.publisher.publishUid == identities.publish && cfg.hostTier.publisher.contentUid == identities.serve && cfg.hostTier.publisher.contentUid != cfg.hostTier.publisher.publishUid && cfg.hostTier.publisher.contentGid == 845);
          message = "Terrane publisher configuration must match the deployed socket and service/content identities.";
        }
        {
          assertion = cfg.hostTier.quota == null || cleanPath cfg.hostTier.quota.socketPath;
          message = "Terrane quota socket must use a canonical absolute path.";
        }
        {
          assertion = !cfg.hostHelper.enable || cfg.hostTier.quota == null || (cfg.hostTier.quota.socketPath == "/run/aos-terrane-host/quota.sock" && cfg.hostTier.quota.configurationEpoch == cfg.hostHelper.epoch);
          message = "Terrane local quota socket and epoch must match the configured host helper.";
        }
        {
          assertion = !cfg.hostHelper.enable || builtins.all (name: let domain = cfg.hostTier.domains.${name}; in domain.quotaOwnerId == null || builtins.any (owner: owner.domain == name && owner.ownerId == domain.quotaOwnerId) cfg.hostHelper.owners) (builtins.attrNames cfg.hostTier.domains);
          message = "Terrane per-domain quota owner IDs must match the local helper's explicit assignments.";
        }

        {
          assertion = builtins.all cleanPath declaredRoots;
          message = "Terrane host roots must be canonical absolute paths without traversal or trailing separators.";
        }
        {
          assertion = uniqueRoots && builtins.all (root: cfg.hostTier.path == root || !overlaps cfg.hostTier.path root) roots;
          message = "Terrane host and domain roots must not overlap.";
        }
        {
          assertion = builtins.all (domain: builtins.match "(public|tenant:.+|group:.+|private:.+)" domain != null) (builtins.attrNames cfg.hostTier.domains);
          message = "Terrane disclosure domains must use canonical domain names.";
        }
        {
          assertion = builtins.all (name: effectiveWipe name cfg.hostTier.domains.${name} != "zero") (builtins.attrNames cfg.hostTier.domains);
          message = "Terrane sealed host tiers cannot honor wipe=zero, including the private-domain default (D-128).";
        }
        {
          assertion = builtins.length (lib.unique (map (exposure: exposure.id) cfg.exposures)) == builtins.length cfg.exposures;
          message = "Terrane exposure IDs must be unique.";
        }
        {
          assertion = builtins.all (ref: !(lib.hasPrefix "file:/nix/store/" ref)) (lib.optional (cfg.tokens.hostToken != null) cfg.tokens.hostToken ++ map (exposure: exposure.token) cfg.exposures);
          message = "Terrane credential references must not point into the Nix store.";
        }
      ];
    environment.etc."terrane/terrane.toml".text = toml.toTOML configuration;
    environment.systemPackages = [cfg.package];
    aos.users.users = builtins.listToAttrs (map (role: {
        name = userFor role;
        value = {
          uid = identities.${role};
          group = userFor role;
          shell = "/sbin/nologin";
          description = "Terrane ${role} role";
          extraGroups = groupsFor role;
        };
      })
      roleNames);
    aos.users.groups =
      builtins.listToAttrs (map (role: {
          name = userFor role;
          value.gid = identities.${role};
        })
        roleNames)
      // {
        terrane-cache.gid = 844;
        terrane-content.gid = 845;
        terrane-maintenance.gid = 846;
      };
    # The root stays root-owned: cache identities cannot rename publisher roots.
    # Publisher-private directories are intentionally not readable by path by
    # other roles; verified read-only descriptors cross the process boundary.
    environment.etc."tmpfiles.d/terrane.conf".text =
      "d /run/terrane-publish 2750 terrane-publish terrane-content - -\n"
      # Existing listener names survive until the original owner is stopped and
      # custody is reconciled. Tmpfiles never unlinks a potentially live socket.
      + lib.optionalString maintenanceEnabled "d ${maintenance.runtimeRoot} 2750 terrane terrane-maintenance - -\n"
      + lib.optionalString (!(builtins.elem cfg.hostTier.path roots)) "d ${cfg.hostTier.path} 0755 root root - -\n"
      + lib.concatMapStrings (entry: let
        root = entry.path;
        # Ordinary metadata leaves may be world-readable. Preserve the native
        # enrollment traversal boundary for every non-public domain.
        custody =
          if entry.domain == "public"
          then "0755 root root"
          else "0750 root terrane-content";
      in
        ''
          d ${root} ${custody} - -
          d ${root}/state 0755 root root - -
          d ${root}/state/cache 2770 terrane terrane-cache - -
          d ${root}/state/publication 0700 terrane-publish terrane-publish - -
          d ${root}/sealed 0700 terrane-publish terrane-publish - -
          d ${root}/staging 0700 terrane-publish terrane-publish - -
          d ${root}/pending-delete 0700 terrane-publish terrane-publish - -
        ''
        + lib.concatMapStrings (name: "d ${root}/${name} 2770 terrane terrane-content - -\n") ["chunks" "objects" "quarantine"])
      domainRoots;
    systemd.slices.aos-control = {description = "AOS control services";};
    systemd.slices.aos-view-services = {description = "AOS filesystem view services outside consumer freezer domains";};
    systemd.services = builtins.listToAttrs (map (role: {
      name = "terrane-${role}";
      value = service role;
    }) (builtins.filter (role: cfg.roles.${role}.enable) roleNames));
    systemd.timers.terrane-gc = lib.mkIf cfg.roles.gc.enable {
      description = "Collect the Terrane host-local cache";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.gc.interval;
        Persistent = true;
        Unit = "terrane-gc.service";
      };
    };
  };
}
