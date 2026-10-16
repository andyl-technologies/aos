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
  # Reject traversal and unit-file metacharacters before paths reach tmpfiles
  # or systemd. Parent ownership is part of the publisher's security boundary.
  pathType = types.strMatching "/[A-Za-z0-9_./-]+";
  cleanPath = path: path != "/" && builtins.all (part: part != ".." && part != "." && part != "") (builtins.tail (lib.splitString "/" path));
  referenceType = types.strMatching "(file:/[^[:space:]]+|secret:[^[:space:]]+|anonymous:[^[:space:]]+)";
  option = type: default: description: lib.mkOption {inherit type default description;};
  domainType = types.submodule {
    options = {
      path = lib.mkOption {
        type = pathType;
        description = "Absolute filesystem root for this disclosure domain.";
      };
      wipe = option (types.nullOr (types.enum ["none" "zero"])) null "Wipe policy; unset defaults to zero for private domains and none otherwise (DOM-18). Explicit policies are preserved.";
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
    lib.optional (role == "serve" || role == "gc") "terrane-cache"
    ++ lib.optional (role == "serve" || role == "gc" || role == "publish") "terrane-content";
  publicRoot = (cfg.hostTier.domains.public or {path = cfg.hostTier.path;}).path;
  roots = [publicRoot] ++ lib.mapAttrsToList (_: domain: domain.path) (builtins.removeAttrs cfg.hostTier.domains ["public"]);
  declaredRoots = lib.unique ([cfg.hostTier.path] ++ roots);
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;
  uniqueRoots = builtins.all (a: builtins.all (b: a == b || !overlaps a b) roots) roots && builtins.length (lib.unique roots) == builtins.length roots;
  writable = role:
    if role == "publish"
    then ["/run/terrane-publish"] ++ builtins.concatMap (root: ["${root}/sealed" "${root}/staging" "${root}/pending-delete" "${root}/state/publication" "${root}/chunks" "${root}/objects" "${root}/quarantine"]) roots
    else if role == "serve" || role == "gc"
    then builtins.concatMap (root: ["${root}/state/cache" "${root}/chunks" "${root}/objects" "${root}/quarantine"]) roots
    else [];
  configuration = {
    store = cfg.store;
    locality = {inherit (cfg.locality) region zone host;};
    host_tier = {
      path = cfg.hostTier.path;
      size_bytes = cfg.hostTier.sizeBytes;
      reassembly = cfg.hostTier.reassembly;
      domains =
        lib.mapAttrs (name: domain: {
          inherit (domain) path;
          wipe =
            if domain.wipe != null
            then domain.wipe
            else if lib.hasPrefix "private:" name
            then "zero"
            else "none";
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
    after = ["systemd-tmpfiles-setup.service"] ++ lib.optional (cfg.hostHelper.enable && role != "realize") "aos-terrane-host-quota.service";
    requires = ["systemd-tmpfiles-setup.service"] ++ lib.optional (cfg.hostHelper.enable && role != "realize") "aos-terrane-host-quota.service";
    serviceConfig = {
      Type =
        if role == "gc"
        then "oneshot"
        else "simple";
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
      PrivateNetwork = role == "publish" || role == "realize";
      RestrictAddressFamilies =
        if role == "publish" || role == "realize"
        then "AF_UNIX"
        else "AF_UNIX AF_INET AF_INET6";
      RestrictNamespaces = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      ReadWritePaths = writable role;
      InaccessiblePaths = lib.optionals (role != "publish") (builtins.concatMap (root: ["${root}/sealed" "${root}/staging" "${root}/pending-delete" "${root}/state/publication"]) roots);
    };
  };
in {
  imports = [./_host-quota.nix];

  options.aos.terrane = {
    enable = lib.mkEnableOption "the Terrane host tier";
    package = option types.package pkgs.terrane "AOS-built Terrane program.";
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
      path = option pathType "/var/lib/terrane" "Absolute host-tier root.";
      sizeBytes = lib.mkOption {
        type = types.addCheck types.int (value: value > 0);
        description = "Maximum host-tier bytes; capacity must be explicit.";
      };
      reassembly = option (types.enum ["never" "always"]) "never" "T2 object reassembly policy.";
      domains = option (types.attrsOf domainType) {} "Domain-specific roots; separate filesystems must be provisioned by the operator when isolation requires them.";
    };
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
    assertions = [
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
      };
    # The root stays root-owned: cache identities cannot rename publisher roots.
    # Publisher-private directories are intentionally not readable by path by
    # other roles; verified read-only descriptors cross the process boundary.
    environment.etc."tmpfiles.d/terrane.conf".text =
      "d /run/terrane-publish 2750 terrane-publish terrane-content - -\n"
      + lib.optionalString (publicRoot != cfg.hostTier.path) "d ${cfg.hostTier.path} 0755 root root - -\n"
      + lib.concatMapStrings (root:
        ''
          d ${root} 0755 root root - -
          d ${root}/state 0755 root root - -
          d ${root}/state/cache 2770 terrane terrane-cache - -
          d ${root}/state/publication 0700 terrane-publish terrane-publish - -
          d ${root}/sealed 0700 terrane-publish terrane-publish - -
          d ${root}/staging 0700 terrane-publish terrane-publish - -
          d ${root}/pending-delete 0700 terrane-publish terrane-publish - -
        ''
        + lib.concatMapStrings (name: "d ${root}/${name} 2770 terrane terrane-content - -\n") ["chunks" "objects" "quarantine"])
      roots;
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
