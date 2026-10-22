##! Host-supplied quota inspection and explicit provisioning (D-123/D-125).
{
  config,
  lib,
  pkgs,
  ...
}: let
  terrane = config.aos.terrane;
  cfg = terrane.hostHelper;
  types = lib.types;
  toml = lib.formats.toml {inherit lib pkgs;};
  option = type: default: description: lib.mkOption {inherit type default description;};
  positive = types.addCheck types.int (value: value > 0);
  absolute = types.strMatching "/[A-Za-z0-9_./-]+";
  requiredLabels = ["layout-root" "chunks" "objects" "sealed" "staging" "quarantine" "pending-delete" "state"];
  publicRoot = (terrane.hostTier.domains.public or {path = terrane.hostTier.path;}).path;
  domainRoots = lib.mapAttrs (_: domain: domain.path) terrane.hostTier.domains // {public = publicRoot;};
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;
  ledgerDirectory = "/var/lib/terrane-host";
  projectClaimsDirectory = "${ledgerDirectory}/project-claims";
  ledgerPath = "${ledgerDirectory}/ledger.toml";
  socketDirectory = "/run/aos-terrane-host";
  configPath = "/etc/terrane-host/host.toml";
  administrativeRoot = domain:
    (terrane.hostTier.domains.${domain} or {administrativeRoot = null;}).administrativeRoot;
  expectedRoots = domain: let
    root = domainRoots.${domain};
    administrative = administrativeRoot domain;
  in
    map (label: {
      roleDirectory = label;
      path =
        if label == "layout-root"
        then root
        else "${root}/${label}";
    })
    requiredLabels
    ++ lib.optional (administrative != null || (domain == "public" && publicRoot != terrane.hostTier.path)) {
      roleDirectory = "administrative-root";
      path =
        if administrative != null
        then administrative
        else terrane.hostTier.path;
    };
  sameRoots = owner:
    builtins.hasAttr owner.domain domainRoots
    && builtins.length owner.roots == builtins.length (expectedRoots owner.domain)
    && builtins.all (expected: builtins.any (root: root.roleDirectory == expected.roleDirectory && root.path == expected.path) owner.roots) (expectedRoots owner.domain);
  configuration =
    {
      socket = "${socketDirectory}/quota.sock";
      epoch = cfg.epoch;
      tier_charge_budget_bytes = terrane.hostTier.sizeBytes;
      owners =
        map (owner: {
          owner_id = owner.ownerId;
          inherit (owner) domain;
          project_id = owner.projectId;
          hard_limit_bytes = owner.hardLimitBytes;
          allowed_client_uids = owner.allowedClientUids;
          roots =
            map (root: {
              role_directory = root.roleDirectory;
              inherit (root) path;
            })
            owner.roots;
        })
        cfg.owners;
    }
    // lib.optionalAttrs (cfg.projectCensus != null) {
      project_census = {
        retained_inodes = cfg.projectCensus.retainedInodes;
        directory_entries = cfg.projectCensus.directoryEntries;
        depth = cfg.projectCensus.depth;
      };
    };
  commonService = {
    User = "root";
    Group = "root";
    Slice = "aos-control.slice";
    UMask = "0077";
    # Each bounded allocation-scaffold directory retains native descriptors
    # and its parent binding throughout the inspector's lifetime.
    # Census requests serialize their additional retained descriptors; ordinary
    # query workers keep the existing scaffold and connection allowance.
    LimitNOFILE =
      8192
      + (
        if cfg.projectCensus == null
        then 0
        else cfg.projectCensus.retainedInodes + 3
      );
    NoNewPrivileges = true;
    AmbientCapabilities = "";
    PrivateNetwork = true;
    RestrictAddressFamilies = "AF_UNIX";
    PrivateDevices = true;
    PrivateUsers = false;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    RestrictNamespaces = true;
  };
  executable =
    if cfg.package == null
    then throw "Terrane hostHelper requires an explicit AOS-built helper package"
    else "${cfg.package}/bin/aos-terrane-host";
  command = subcommand: "${executable} ${subcommand} --config ${configPath} --ledger ${ledgerPath}";
in {
  options.aos.terrane.hostHelper = {
    enable = lib.mkEnableOption "host-supplied Terrane project-quota inspection";
    package = option (types.nullOr types.package) null "Explicit AOS-built host helper; no package is selected implicitly.";
    epoch = option (types.nullOr (types.strMatching "[0-9a-f]{32}")) null "Explicit provisioning epoch persisted in the host-owned ledger.";
    projectCensus =
      option (types.nullOr (types.submodule {
        options = {
          retainedInodes = option (types.addCheck positive (value: value <= 65536)) 1024 "Maximum distinct inode descriptors held through one serialized census.";
          directoryEntries = option (types.addCheck positive (value: value <= 1048576)) 65536 "Maximum visited entries, including aliases and excluded names.";
          depth = option (types.addCheck positive (value: value <= 256)) 64 "Maximum traversal depth beneath configured roots.";
        };
      }))
      null "Explicit read-only inode census bounds; null disables census queries.";
    owners = option (types.listOf (types.submodule {
      options = {
        ownerId = lib.mkOption {
          type = types.strMatching ".{1,256}";
          description = "Stable explicit allocation owner identifier.";
        };
        domain = lib.mkOption {
          type = types.str;
          description = "Canonical disclosure domain owning this project.";
        };
        projectId = lib.mkOption {
          type = types.addCheck positive (value: value <= 4294967295);
          description = "Explicit nonzero kernel project ID.";
        };
        hardLimitBytes = lib.mkOption {
          type = types.addCheck positive (value: value == builtins.div value 1024 * 1024);
          description = "Finite 1024-byte-aligned quota charge limit.";
        };
        allowedClientUids = option (types.listOf types.int) [840 841 843] "Exact serve, publisher and GC client identities allowed to query this owner.";
        roots = lib.mkOption {
          type = types.listOf (types.submodule {
            options = {
              roleDirectory = lib.mkOption {
                type = types.enum (requiredLabels ++ ["administrative-root"]);
                description = "Registered host allocation class label.";
              };
              path = lib.mkOption {
                type = absolute;
                description = "Explicit absolute provisioned directory.";
              };
            };
          });
          description = "Complete layout/class roots and explicit administrative root when public storage is overridden.";
        };
      };
    })) [] "Complete explicit finite project assignments; limits share the single tier budget.";
  };

  config = lib.mkIf (terrane.enable && cfg.enable) {
    assertions = [
      {
        assertion = cfg.package != null && cfg.epoch != null;
        message = "Terrane quota helper requires an explicit package and provisioning epoch.";
      }
      {
        assertion = builtins.length cfg.owners == builtins.length (builtins.attrNames domainRoots) && builtins.all sameRoots cfg.owners;
        message = "Terrane quota owners must cover every resolved domain root and all registered allocation classes exactly once.";
      }
      {
        assertion = builtins.length (lib.unique (map (owner: owner.domain) cfg.owners)) == builtins.length cfg.owners && builtins.length (lib.unique (map (owner: owner.ownerId) cfg.owners)) == builtins.length cfg.owners && builtins.length (lib.unique (map (owner: owner.projectId) cfg.owners)) == builtins.length cfg.owners;
        message = "Terrane allocation domains, owner IDs and project IDs must be unique.";
      }
      {
        assertion = builtins.foldl' (sum: owner: sum + owner.hardLimitBytes) 0 cfg.owners <= terrane.hostTier.sizeBytes;
        message = "Terrane finite project hard limits must fit the single tier quota-charge budget.";
      }
      {
        assertion = builtins.all (owner: builtins.sort builtins.lessThan owner.allowedClientUids == [840 841 843]) cfg.owners;
        message = "Terrane quota queries allow only the configured serve, publisher and GC identities.";
      }
      {
        assertion = builtins.all (owner: builtins.all (root: !overlaps root.path ledgerDirectory && !overlaps root.path socketDirectory && !overlaps root.path "/etc/terrane-host") owner.roots) cfg.owners;
        message = "Terrane host configuration, runtime socket and provisioning ledger must stay outside content roots.";
      }
    ];
    environment.etc."terrane-host/host.toml" = {
      text = toml.toTOML configuration;
      mode = "0600";
    };
    environment.etc."tmpfiles.d/terrane-host.conf".text = ''
      d ${ledgerDirectory} 0700 root root - -
      d ${projectClaimsDirectory} 0700 root root - -
      d ${socketDirectory} 0755 root root - -
    '';
    # Provisioning is an explicit host-admin action; boot never reassigns IDs.
    systemd.services.aos-terrane-host-provision = {
      description = "Provision explicitly assigned Terrane host project quotas";
      after = ["systemd-tmpfiles-setup.service"];
      requires = ["systemd-tmpfiles-setup.service"];
      serviceConfig =
        commonService
        // {
          Type = "oneshot";
          ExecStart = command "provision";
          # Root is not a member of the content groups; restoring setgid
          # after restrictive custody modes therefore also needs CAP_FSETID.
          CapabilityBoundingSet = "CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_CHOWN CAP_FSETID";
          ReadWritePaths = [ledgerDirectory projectClaimsDirectory] ++ lib.unique (builtins.concatMap (owner: map (root: root.path) owner.roots) cfg.owners);
        };
    };
    systemd.services.aos-terrane-host-quota = {
      description = "Inspect Terrane host quotas through authenticated read-only queries";
      wantedBy = ["multi-user.target"];
      after = ["systemd-tmpfiles-setup.service"];
      requires = ["systemd-tmpfiles-setup.service"];
      serviceConfig =
        commonService
        // {
          Type = "simple";
          ExecStart = command "serve";
          CapabilityBoundingSet = "CAP_SYS_ADMIN CAP_DAC_READ_SEARCH";
          # The host-global ownership registry is authenticated by native
          # identity checks; the query process has no mutation path to it.
          ReadOnlyPaths = [projectClaimsDirectory];
          ReadWritePaths = [socketDirectory];
        };
    };
  };
}
