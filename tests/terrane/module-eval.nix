##! Declarative Terrane configuration and service-isolation checks (PKG-8/10).
{
  pkgs,
  lib,
  mkSystem,
}: let
  fixture = {
    aos.terrane = {
      enable = true;
      store = "disk(/var/lib/terrane)";
      hostTier.sizeBytes = 1073741824;
    };
  };
  evaluate = extra:
    (mkSystem {
      modules = [fixture extra];
      systemName = "terrane-module-eval";
    }).config;
  enabled = evaluate {};
  disabled =
    (mkSystem {
      modules = [];
      systemName = "terrane-module-disabled";
    }).config;
  roles = ["serve" "publish" "realize" "gc"];
  service = role: enabled.systemd.services."terrane-${role}".serviceConfig;
  checksPass = cfg: builtins.all (entry: entry.assertion) cfg.assertions;
  rejected = extra: let
    attempt = builtins.tryEval (builtins.deepSeq (evaluate extra).environment.etc."terrane/terrane.toml".text (checksPass (evaluate extra)));
  in
    !attempt.success || !attempt.value;
  file = enabled.environment.etc."terrane/terrane.toml".text;
  domain = evaluate {
    aos.terrane.hostTier.domains."private:example" = {
      path = "/var/lib/terrane-private";
      wipe = "none";
    };
    aos.terrane.sdkOutputRoots = ["/srv"];
    aos.terrane.exposures = [
      {
        id = "sdk";
        view = "refs/heads/main";
        surface = "sdk";
        at = "/srv/sdk";
        token = "file:/run/terrane/token";
        mode.reader = "pinned";
      }
    ];
  };
  domainFile = domain.environment.etc."terrane/terrane.toml".text;
  assertions = [
    {
      name = "valid-fixture";
      pass = checksPass enabled;
    }
    {
      name = "disabled-inert";
      pass = !(disabled.environment.etc ? "terrane/terrane.toml") && !(disabled.systemd.services ? terrane-serve) && !(disabled.aos.users.users ? terrane);
    }
    {
      name = "one-shared-config";
      pass = builtins.all (role: lib.hasInfix "--config /etc/terrane/terrane.toml --role ${role}" (service role).ExecStart) roles && !(lib.hasInfix "role =" file);
    }
    {
      name = "schema-spelling";
      pass = builtins.all (word: lib.hasInfix word file) ["store =" "[host_tier]" "size_bytes = 1073741824" "reassembly = \"never\"" "issuer_public_keys = []"] && !(lib.hasInfix "sizeBytes" file);
    }
    {
      name = "explicit-private-none-preserved";
      pass = lib.hasInfix "wipe = \"none\"" domainFile && lib.hasInfix "[host_tier.domains.\"private:example\"]" domainFile && lib.hasInfix "[[expose]]" domainFile;
    }
    {
      name = "distinct-identities";
      pass = builtins.length (lib.unique (map (role: (service role).User) roles)) == 4 && enabled.aos.users.users.terrane.uid == 840 && enabled.aos.users.users.terrane-publish.uid == 841;
    }
    {
      name = "unprivileged-roles";
      pass = builtins.all (role: let unit = service role; in unit.CapabilityBoundingSet == "" && unit.AmbientCapabilities == "" && unit.NoNewPrivileges && unit.RestrictNamespaces && unit.PrivateDevices && unit.ProtectSystem == "strict" && !unit.DynamicUser) roles;
    }
    {
      name = "networkless-publisher-realizer";
      pass = builtins.all (role: (service role).PrivateNetwork && (service role).RestrictAddressFamilies == "AF_UNIX") ["publish" "realize"];
    }
    {
      name = "publisher-write-custody";
      pass = builtins.elem "/var/lib/terrane/sealed" (service "publish").ReadWritePaths && builtins.all (role: !(builtins.elem "/var/lib/terrane/sealed" (service role).ReadWritePaths) && builtins.elem "/var/lib/terrane/sealed" (service role).ReadOnlyPaths && !(builtins.elem "/var/lib/terrane/sealed" (service role).InaccessiblePaths)) ["serve" "realize" "gc"] && lib.hasInfix "d /var/lib/terrane 0755 root root" enabled.environment.etc."tmpfiles.d/terrane.conf".text && lib.hasInfix "d /var/lib/terrane/staging 0700 terrane-publish terrane-publish" enabled.environment.etc."tmpfiles.d/terrane.conf".text;
    }
    {
      name = "publisher-private-roots-preserve-native-identities";
      pass = builtins.all (role: (service role).ReadOnlyPaths == map (suffix: "/var/lib/terrane/${suffix}") ["sealed" "staging" "pending-delete" "state/publication"]) ["serve" "realize" "gc"] && (service "publish").ReadOnlyPaths == [];
    }
    {
      name = "slice-placement";
      pass = (service "serve").Slice == "aos-control.slice" && builtins.all (role: (service role).Slice == "aos-view-services.slice") ["publish" "realize" "gc"];
    }
    {
      name = "role-disable";
      pass = let
        cfg = evaluate {
          aos.terrane.roles.gc.enable = false;
          aos.terrane.roles.realize.enable = false;
        };
      in
        !(cfg.systemd.services ? terrane-gc) && !(cfg.systemd.services ? terrane-realize) && !(cfg.systemd.timers ? terrane-gc);
    }
    {
      name = "host-local-gc-timer";
      pass = enabled.systemd.timers.terrane-gc.timerConfig.Unit == "terrane-gc.service" && (service "gc").Type == "oneshot";
    }
    {
      name = "relative-root-refused";
      pass = rejected {aos.terrane.hostTier.path = "relative";};
    }
    {
      name = "traversal-root-refused";
      pass = rejected {aos.terrane.hostTier.path = "/var/lib/../sealed";};
    }
    {
      name = "overlapping-root-refused";
      pass = rejected {aos.terrane.hostTier.domains.public.path = "/var/lib/terrane/public";};
    }
    {
      name = "zero-quota-refused";
      pass = rejected {aos.terrane.hostTier.sizeBytes = 0;};
    }
    {
      name = "unsupported-wipe-refused";
      pass = rejected {
        aos.terrane.hostTier.domains.public = {
          path = "/var/lib/public";
          wipe = "volatile";
        };
      };
    }
    {
      name = "unsupported-reassembly-refused";
      pass = rejected {aos.terrane.hostTier.reassembly = "smart";};
    }
    {
      name = "inline-token-refused";
      pass = rejected {aos.terrane.tokens.hostToken = "raw-secret";};
    }
    {
      name = "store-token-refused";
      pass = rejected {aos.terrane.tokens.hostToken = "file:/nix/store/token";};
    }
    {
      name = "noncanonical-domain-refused";
      pass = rejected {aos.terrane.hostTier.domains.arbitrary.path = "/var/lib/domain";};
    }
  ];
  quotaLabels = ["layout-root" "chunks" "objects" "sealed" "staging" "quarantine" "pending-delete" "state"];
  quotaOwner = domain: root: id: {
    ownerId = "owner-${domain}";
    inherit domain;
    projectId = id;
    hardLimitBytes = 536870912;
    roots =
      map (label: {
        roleDirectory = label;
        path =
          if label == "layout-root"
          then root
          else "${root}/${label}";
      })
      quotaLabels;
  };
  helperFixture = {
    aos.terrane.hostHelper = {
      enable = true;
      # Only a derivation path is inspected; this fixture never executes it.
      package = pkgs.terrane;
      epoch = "00112233445566778899aabbccddeeff";
      owners = [(quotaOwner "public" "/var/lib/terrane" 1001)];
    };
  };
  helper = evaluate helperFixture;
  helperConfig = helper.environment.etc."terrane-host/host.toml".text;
  rejectedHelper = extra: let
    cfg =
      (mkSystem {
        modules = [fixture helperFixture extra];
        systemName = "terrane-helper-negative";
      }).config;
    attempt = builtins.tryEval (builtins.deepSeq cfg.environment.etc."terrane-host/host.toml".text (checksPass cfg));
  in
    !attempt.success || !attempt.value;
  nativeFixture = {
    aos.terrane.hostTier = {
      publisher = {
        socketPath = "/run/terrane-publish/publisher.sock";
        serveUid = 840;
        publishUid = 841;
        contentUid = 840;
        contentGid = 845;
        maxConnections = 8;
      };
      quota = {
        socketPath = "/run/aos-terrane-host/quota.sock";
        configurationEpoch = "00112233445566778899aabbccddeeff";
      };
      domains.public = {
        path = "/var/lib/terrane";
        quotaOwnerId = "owner-public";
        publisher = {
          retirementGraceMs = 5000;
          chunkProfile = "cdc-1m";
          chunkSeed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        };
      };
    };
  };
  native =
    (mkSystem {
      modules = [fixture nativeFixture];
      systemName = "terrane-native-config";
    }).config;
  nativeFile = native.environment.etc."terrane/terrane.toml".text;
  rejectedNative = extra: let
    cfg =
      (mkSystem {
        modules = [fixture {aos.terrane = lib.recursiveUpdate nativeFixture.aos.terrane (extra.aos.terrane or {});} helperFixture];
        systemName = "terrane-native-config-negative";
      }).config;
    attempt = builtins.tryEval (builtins.deepSeq cfg.environment.etc."terrane/terrane.toml".text (checksPass cfg));
  in
    !attempt.success || !attempt.value;
  cacheFixture = {
    stateGid = 844;
    capacityBytes = 25165824;
    lowWatermarkBytes = 16777216;
    probationBytes = 65536;
    releaseGraceSeconds = 30;
    scanLimit = 64;
    maxReadBytes = 2097152;
    stateBytes = 65536;
    stateRecords = 64;
    inventoryEntries = 128;
    queuedCommands = 4;
    metadataSyncHoldBytes = 262144;
    publisherWaitBudgetMs = 10000;
    consumerLeaseSeconds = 30;
    lower = {
      budgetMs = 10000;
      failureThreshold = 3;
      probeIntervalMs = 5000;
    };
    portable = {
      maxFileBytes = 67108864;
      maxInputBytes = 268435456;
      maxFiles = 4096;
      maxSelectedBytes = 33554432;
    };
  };
  cached = evaluate (lib.recursiveUpdate nativeFixture {
    aos.terrane.hostTier.domains.public.cache = cacheFixture;
  });
  cachedFile = cached.environment.etc."terrane/terrane.toml".text;
  surfaceIndexFixture = {
    maxEntries = 64;
    maxNodeBytes = 131072;
    maxIndexBytes = 65536;
    capacityBytes = 1048576;
    futureHoldBytes = 327680;
  };
  localFixture = {
    aos.terrane = {
      store = lib.mkForce "bucket(file:///var/lib/terrane-bucket)";
      localRepository = {
        authorityDirectory = "/var/lib/terrane-authority";
        issuer = "configured-operator";
        keyId = "current-key";
        ownerUid = 840;
        storeName = "local";
        domain = "public";
        defaultPrivateDomain = "private:operator";
        currentReference = "refs/heads/_/main";
        acl = [
          {
            principal = "reader";
            verbs = ["read"];
          }
        ];
        timing = {
          maximumMs = 30000;
          graceMs = 60000;
          marginMs = 10000;
        };
      };
    };
  };
  local = evaluate localFixture;
  localFile = local.environment.etc."terrane/terrane.toml".text;
  localConfig = extra:
    (mkSystem {
      modules = [fixture {aos.terrane = lib.recursiveUpdate localFixture.aos.terrane (extra.aos.terrane or {});}];
      systemName = "terrane-local-repository-eval";
    }).config;
  rejectedLocal = extra: let
    cfg = localConfig extra;
    attempt = builtins.tryEval (builtins.deepSeq cfg.environment.etc."terrane/terrane.toml".text (checksPass cfg));
  in
    !attempt.success || !attempt.value;
  extraAssertions = [
    {
      name = "host-global-project-registry-root-custody";
      pass =
        lib.hasInfix "d /var/lib/terrane-host/project-claims 0700 root root" helper.environment.etc."tmpfiles.d/terrane-host.conf".text
        && helper.systemd.services.aos-terrane-host-provision.serviceConfig.User == "root"
        && helper.systemd.services.aos-terrane-host-quota.serviceConfig.User == "root";
    }
    {
      name = "host-global-project-registry-helper-access";
      pass =
        builtins.elem "/var/lib/terrane-host/project-claims" helper.systemd.services.aos-terrane-host-provision.serviceConfig.ReadWritePaths
        && helper.systemd.services.aos-terrane-host-quota.serviceConfig.ReadOnlyPaths == ["/var/lib/terrane-host/project-claims"]
        && helper.systemd.services.aos-terrane-host-quota.serviceConfig.ReadWritePaths == ["/run/aos-terrane-host"]
        && lib.hasInfix "ReadOnlyPaths=/var/lib/terrane-host/project-claims" helper.system.build.systemdUnitBodies."aos-terrane-host-quota.service".text;
    }
    {
      name = "host-global-project-registry-role-inaccessible";
      pass = builtins.all (role:
        builtins.elem "-/var/lib/terrane-host/project-claims" (service role).InaccessiblePaths
        && !(builtins.elem "/var/lib/terrane-host/project-claims" (service role).ReadWritePaths))
      roles;
    }
    {
      name = "host-global-project-registry-content-overlap-refused";
      pass = rejected {aos.terrane.hostTier.path = "/var/lib/terrane-host/project-claims/content";};
    }
    {
      name = "host-global-project-registry-content-ancestor-refused";
      pass = rejected {aos.terrane.hostTier.path = "/var/lib/terrane-host";};
    }

    {
      name = "native-complete-override-positive-control";
      pass = !rejectedNative {aos.terrane.hostTier.publisher.maxConnections = 16;};
    }
    {
      name = "local-complete-override-positive-control";
      pass = !rejectedLocal {aos.terrane.localRepository.timing.maximumMs = 20000;};
    }

    {
      name = "local-repository-explicit-projection";
      pass =
        checksPass local
        && !(lib.hasInfix "_module" localFile)
        && builtins.all (field: lib.hasInfix field localFile) ["[local_repository]" "authority_directory = \"/var/lib/terrane-authority\"" "owner_uid = 840" "current_reference = \"refs/heads/_/main\"" "maximum_ms = 30000" "principal = \"reader\"" "verbs = [\"read\"]"]
        && !(lib.hasInfix "policy_authority" localFile)
        && !(lib.hasInfix "/var/lib/terrane-authority" local.environment.etc."tmpfiles.d/terrane.conf".text);
    }
    {
      name = "local-repository-empty-acl-denies";
      pass = lib.hasInfix "acl = []" (localConfig {aos.terrane.localRepository.acl = lib.mkForce [];}).environment.etc."terrane/terrane.toml".text;
    }
    {
      name = "local-repository-optional-policy-authority";
      pass = lib.hasInfix "policy_authority = \"refs/heads/_/policy\"" (localConfig {aos.terrane.localRepository.policyAuthority = "refs/heads/_/policy";}).environment.etc."terrane/terrane.toml".text;
    }
    {
      name = "local-repository-uid-mismatch-refused";
      pass = rejectedLocal {aos.terrane.localRepository.ownerUid = 900;};
    }
    {
      name = "local-repository-invalid-uid-refused";
      pass = rejectedLocal {aos.terrane.localRepository.ownerUid = 4294967295;};
    }
    {
      name = "local-repository-invalid-timing-refused";
      pass = rejectedLocal {aos.terrane.localRepository.timing.maximumMs = 50000;};
    }
    {
      name = "local-repository-invalid-verb-refused";
      pass = rejectedLocal {
        aos.terrane.localRepository.acl = lib.mkForce [
          {
            principal = "reader";
            verbs = ["write"];
          }
        ];
      };
    }
    {
      name = "local-repository-invalid-head-refused";
      pass = rejectedLocal {aos.terrane.localRepository.currentReference = "refs/tags/_/v1";};
    }
    {
      name = "local-repository-shared-with-other-roles";
      pass = builtins.all (role: builtins.hasAttr "terrane-${role}" local.systemd.services) roles;
    }
    {
      name = "local-repository-absent-by-default";
      pass = !(lib.hasInfix "local_repository" file);
    }

    {
      name = "publisher-content-identity-separation-refused";
      pass = rejectedNative {aos.terrane.hostTier.publisher.contentUid = 841;};
    }

    {
      name = "role-user-override-refused";
      pass = rejected {systemd.services.terrane-publish.serviceConfig.User = lib.mkForce "unrelated";};
    }
    {
      name = "role-capability-override-refused";
      pass = rejected {systemd.services.terrane-publish.serviceConfig.CapabilityBoundingSet = lib.mkForce "CAP_SYS_ADMIN";};
    }
    {
      name = "role-private-user-namespace-refused";
      pass = rejected {systemd.services.terrane-publish.serviceConfig.PrivateUsers = true;};
    }

    {
      name = "dedicated-role-accounts-nonlogin";
      pass = builtins.all (name: enabled.aos.users.users.${name}.shell == "/sbin/nologin") ["terrane" "terrane-publish" "terrane-realize" "terrane-gc"];
    }
    {
      name = "reserved-uid-reuse-refused";
      pass = rejected {aos.users.users.unrelated.uid = 841;};
    }
    {
      name = "reserved-group-alias-refused";
      pass = rejected {aos.users.groups.unrelated.gid = 845;};
    }
    {
      name = "foreign-content-membership-refused";
      pass = rejected {
        aos.users.users.unrelated = {
          uid = 900;
          extraGroups = ["terrane-content"];
        };
      };
    }
    {
      name = "foreign-publisher-unit-refused";
      pass = rejected {
        systemd.services.unrelated.serviceConfig = {
          User = "terrane-publish";
          ExecStart = "${pkgs.terrane}/bin/terrane";
        };
      };
    }
    {
      name = "role-proc-view-declared";
      pass = builtins.all (role: (service role).ProtectProc == "invisible" && (service role).ProcSubset == "pid") roles;
    }
    {
      name = "host-helper-bounded-descriptor-limit";
      pass = helper.systemd.services.aos-terrane-host-quota.serviceConfig.LimitNOFILE == 8192 && helper.systemd.services.aos-terrane-host-provision.serviceConfig.LimitNOFILE == 8192;
    }
    {
      name = "host-census-explicit-resources-and-descriptor-budget";
      pass = let
        census = evaluate (lib.recursiveUpdate helperFixture {
          aos.terrane.hostHelper.projectCensus = {};
        });
        text = census.environment.etc."terrane-host/host.toml".text;
      in
        checksPass census
        && !(lib.hasInfix "project_census" helperConfig)
        && builtins.all (field: lib.hasInfix field text) ["[project_census]" "retained_inodes = 1024" "directory_entries = 65536" "depth = 64"]
        && census.systemd.services.aos-terrane-host-quota.serviceConfig.LimitNOFILE == 9219;
    }
    {
      name = "host-census-zero-or-excessive-bounds-refused";
      pass = builtins.all rejectedHelper [
        {aos.terrane.hostHelper.projectCensus.retainedInodes = 0;}
        {aos.terrane.hostHelper.projectCensus.retainedInodes = 65537;}
        {aos.terrane.hostHelper.projectCensus.directoryEntries = 1048577;}
        {aos.terrane.hostHelper.projectCensus.depth = 257;}
      ];
    }

    {
      name = "host-helper-summed-domain-budget-refused";
      pass = rejectedHelper {
        aos.terrane.hostTier.domains."tenant:example".path = "/var/lib/terrane-tenant";
        aos.terrane.hostHelper.owners = lib.mkForce [
          (quotaOwner "public" "/var/lib/terrane" 1001 // {hardLimitBytes = 805306368;})
          (quotaOwner "tenant:example" "/var/lib/terrane-tenant" 1002 // {hardLimitBytes = 805306368;})
        ];
      };
    }

    {
      name = "native-runtime-sections-projected";
      pass =
        checksPass native
        && !(lib.hasInfix "_module" nativeFile)
        && builtins.all (field: lib.hasInfix field nativeFile) ["[host_tier.publisher]" "socket_path = \"/run/terrane-publish/publisher.sock\"" "serve_uid = 840" "content_gid = 845" "max_connections = 8" "[host_tier.quota]" "configuration_epoch = \"00112233445566778899aabbccddeeff\"" "quota_owner_id = \"owner-public\"" "retirement_grace_ms = 5000" "chunk_profile = \"cdc-1m\"" "chunk_seed = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\""];
    }
    {
      name = "domain-administrative-roots-projected-independently";
      pass = let
        cfg = evaluate {
          aos.terrane.hostTier.domains = {
            public = {
              path = "/var/lib/terrane-public";
              administrativeRoot = "/var/lib/terrane-admin-public";
            };
            "private:example" = {
              path = "/var/lib/terrane-private";
              administrativeRoot = "/var/lib/terrane-admin-private";
              wipe = "none";
            };
          };
        };
        text = cfg.environment.etc."terrane/terrane.toml".text;
      in
        checksPass cfg
        && lib.hasInfix "administrative_root = \"/var/lib/terrane-admin-public\"" text
        && lib.hasInfix "administrative_root = \"/var/lib/terrane-admin-private\"" text;
    }
    {
      name = "sdk-config-has-no-implicit-native-sections";
      pass = !(lib.hasInfix "[host_tier.publisher]" file) && !(lib.hasInfix "[host_tier.quota]" file) && !(lib.hasInfix "chunk_seed" file);
    }
    {
      name = "external-quota-helper-not-enabled";
      pass = !(native.systemd.services ? aos-terrane-host-quota);
    }
    {
      name = "publisher-identity-mismatch-refused";
      pass = rejectedNative {aos.terrane.hostTier.publisher.serveUid = 900;};
    }
    {
      name = "publisher-wrong-socket-refused";
      pass = rejectedNative {aos.terrane.hostTier.publisher.socketPath = "/run/wrong.sock";};
    }
    {
      name = "publisher-connection-bound-refused";
      pass = rejectedNative {aos.terrane.hostTier.publisher.maxConnections = 1025;};
    }
    {
      name = "publisher-seed-encoding-refused";
      pass = rejectedNative {aos.terrane.hostTier.domains.public.publisher.chunkSeed = "not-a-seed";};
    }
    {
      name = "quota-helper-epoch-mismatch-refused";
      pass = rejectedNative {aos.terrane.hostTier.quota.configurationEpoch = "ffeeddccbbaa99887766554433221100";};
    }
    {
      name = "quota-helper-socket-mismatch-refused";
      pass = rejectedNative {aos.terrane.hostTier.quota.socketPath = "/run/external/quota.sock";};
    }
    {
      name = "quota-helper-owner-mismatch-refused";
      pass = rejectedNative {aos.terrane.hostTier.domains.public.quotaOwnerId = "different-owner";};
    }
    {
      name = "provision-custody-caps-host-only";
      pass = helper.systemd.services.aos-terrane-host-provision.serviceConfig.CapabilityBoundingSet == "CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_FOWNER CAP_CHOWN CAP_FSETID" && builtins.all (role: (service role).CapabilityBoundingSet == "") roles;
    }

    {
      name = "public-override-quota-has-explicit-administrative-root";
      pass = let
        owners = [
          (quotaOwner "public" "/var/lib/terrane-public" 1001
            // {
              roots =
                (quotaOwner "public" "/var/lib/terrane-public" 1001).roots
                ++ [
                  {
                    roleDirectory = "administrative-root";
                    path = "/var/lib/terrane";
                  }
                ];
            })
        ];
        cfg =
          (mkSystem {
            modules = [
              fixture
              helperFixture
              {
                aos.terrane.hostTier.domains.public.path = "/var/lib/terrane-public";
                aos.terrane.hostHelper.owners = lib.mkForce owners;
              }
            ];
            systemName = "terrane-helper-public-override";
          }).config;
      in
        checksPass cfg && lib.hasInfix "role_directory = \"administrative-root\"" cfg.environment.etc."terrane-host/host.toml".text;
    }
    {
      name = "host-helper-orders-unprivileged-clients";
      pass =
        builtins.all (role: builtins.elem "aos-terrane-host-quota.service" helper.systemd.services."terrane-${role}".requires) ["serve" "publish" "gc"]
        && !(builtins.elem "aos-terrane-host-quota.service" helper.systemd.services.terrane-realize.requires);
    }
    {
      name = "host-helper-missing-admin-root-refused";
      pass = rejectedHelper {
        aos.terrane.hostTier.domains.public.path = "/var/lib/terrane-public";
        aos.terrane.hostHelper.owners = lib.mkForce [(quotaOwner "public" "/var/lib/terrane-public" 1001)];
      };
    }
    {
      name = "host-helper-misaligned-limit-refused";
      pass = rejectedHelper {aos.terrane.hostHelper.owners = lib.mkForce [(quotaOwner "public" "/var/lib/terrane" 1001 // {hardLimitBytes = 1025;})];};
    }

    {
      name = "host-helper-explicit-config";
      pass =
        checksPass helper
        && helper.environment.etc."terrane-host/host.toml".mode == "0600"
        && builtins.all (field: lib.hasInfix field helperConfig) ["tier_charge_budget_bytes = 1073741824" "role_directory = \"layout-root\"" "project_id = 1001" "allowed_client_uids = [840, 841, 843]"]
        && !(lib.hasInfix "_module" helperConfig);
    }
    {
      name = "host-helper-query-least-authority";
      pass = let
        unit = helper.systemd.services.aos-terrane-host-quota.serviceConfig;
      in
        unit.User
        == "root"
        && unit.CapabilityBoundingSet == "CAP_SYS_ADMIN CAP_DAC_READ_SEARCH"
        && unit.PrivateNetwork
        && unit.RestrictAddressFamilies == "AF_UNIX"
        && unit.ReadWritePaths == ["/run/aos-terrane-host"]
        && lib.hasInfix "serve --config /etc/terrane-host/host.toml --ledger /var/lib/terrane-host/ledger.toml" unit.ExecStart;
    }
    {
      name = "host-helper-provision-manual";
      pass =
        helper.systemd.services.aos-terrane-host-provision.wantedBy
        == []
        && !(builtins.elem "aos-terrane-host-provision.service" helper.systemd.services.aos-terrane-host-quota.requires)
        && lib.hasInfix "provision --config" helper.systemd.services.aos-terrane-host-provision.serviceConfig.ExecStart;
    }
    {
      name = "host-helper-disabled-inert";
      pass = !(enabled.systemd.services ? aos-terrane-host-quota) && !(enabled.environment.etc ? "terrane-host/host.toml");
    }
    {
      name = "host-helper-budget-refused";
      pass = rejectedHelper {aos.terrane.hostHelper.owners = lib.mkForce [(quotaOwner "public" "/var/lib/terrane" 1001 // {hardLimitBytes = 2147483648;})];};
    }
    {
      name = "host-helper-missing-class-refused";
      pass = rejectedHelper {aos.terrane.hostHelper.owners = lib.mkForce [(quotaOwner "public" "/var/lib/terrane" 1001 // {roots = [];})];};
    }
    {
      name = "host-helper-extra-client-refused";
      pass = rejectedHelper {aos.terrane.hostHelper.owners = lib.mkForce [(quotaOwner "public" "/var/lib/terrane" 1001 // {allowedClientUids = [0 840 841 843];})];};
    }
    {
      name = "public-override-has-one-data-layout";
      pass = let
        cfg = evaluate {aos.terrane.hostTier.domains.public.path = "/var/lib/terrane-public";};
        text = cfg.environment.etc."tmpfiles.d/terrane.conf".text;
      in
        checksPass cfg
        && lib.hasInfix "d /var/lib/terrane 0755 root root" text
        && lib.hasInfix "d /var/lib/terrane-public/state/cache" text
        && !(lib.hasInfix "d /var/lib/terrane/state" text)
        && !(builtins.elem "/var/lib/terrane/chunks" cfg.systemd.services.terrane-serve.serviceConfig.ReadWritePaths);
    }

    {
      name = "publisher-socket-parent-custody";
      pass =
        lib.hasInfix "d /run/terrane-publish 2750 terrane-publish terrane-content" enabled.environment.etc."tmpfiles.d/terrane.conf".text
        && (service "publish").Group == "terrane-publish"
        && (service "publish").UMask == "0077"
        && builtins.elem "/run/terrane-publish" (service "publish").ReadWritePaths
        && builtins.all (role: !(builtins.elem "/run/terrane-publish" (service role).ReadWritePaths)) ["serve" "realize" "gc"];
    }

    {
      name = "content-and-pin-state-groups-separated";
      pass =
        enabled.aos.users.groups.terrane-content.gid
        == 845
        && enabled.aos.users.groups.terrane-cache.gid == 844
        && (service "publish").SupplementaryGroups == ["terrane-content"]
        && enabled.aos.users.users.terrane-publish.extraGroups == ["terrane-content"]
        && builtins.all (role: (service role).SupplementaryGroups == ["terrane-cache" "terrane-content"]) ["serve" "gc"]
        && (service "realize").SupplementaryGroups == [];
    }
    {
      name = "publisher-exact-retirement-write-paths";
      pass = (service "publish").ReadWritePaths == ["/run/terrane-publish"] ++ map (path: "/var/lib/terrane/${path}") ["sealed" "staging" "pending-delete" "state/publication" "chunks" "objects" "quarantine"];
    }
    {
      name = "body-and-pin-state-directory-groups";
      pass =
        builtins.all (name: lib.hasInfix "d /var/lib/terrane/${name} 2770 terrane terrane-content" enabled.environment.etc."tmpfiles.d/terrane.conf".text) ["chunks" "objects" "quarantine"]
        && lib.hasInfix "d /var/lib/terrane/state/cache 2770 terrane terrane-cache" enabled.environment.etc."tmpfiles.d/terrane.conf".text;
    }

    {
      name = "module-metadata-excluded";
      pass = !(lib.hasInfix "_module" file) && !(lib.hasInfix "_module" domainFile);
    }

    {
      name = "private-domain-default-zero";
      pass = let
        extra.aos.terrane.hostTier.domains."private:default".path = "/var/lib/terrane-private";
      in
        lib.hasInfix "wipe = \"zero\"" (evaluate extra).environment.etc."terrane/terrane.toml".text
        && rejected extra;
    }
    {
      name = "sealed-host-explicit-zero-refused";
      pass = builtins.all (domain:
        rejected {
          aos.terrane.hostTier.domains.${domain} = {
            path = "/srv/terrane-zero";
            wipe = "zero";
          };
        }) ["public" "tenant:operator" "group:operator" "private:operator"];
    }
    {
      name = "public-domain-default-none";
      pass = lib.hasInfix "wipe = \"none\"" (evaluate {aos.terrane.hostTier.domains.public.path = "/var/lib/terrane-public";}).environment.etc."terrane/terrane.toml".text;
    }
    {
      name = "explicit-private-wipe-preserved";
      pass =
        lib.hasInfix "wipe = \"none\""
        (evaluate {
          aos.terrane.hostTier.domains."private:override" = {
            path = "/var/lib/terrane-private";
            wipe = "none";
          };
        }).environment.etc."terrane/terrane.toml".text;
    }
    {
      name = "absent-mode-fields-pruned";
      pass =
        lib.hasInfix "mode = {}"
        (evaluate {
          aos.terrane.sdkOutputRoots = ["/srv"];
          aos.terrane.exposures = [
            {
              id = "default-mode";
              view = "refs/heads/main";
              surface = "sdk";
              at = "/srv/sdk";
              token = "anonymous:refs/heads/main:read";
            }
          ];
        }).environment.etc."terrane/terrane.toml".text;
    }

    {
      name = "structured-input-only";
      pass = let
        options =
          (lib.evalModules {
            modules = [../../modules/terrane/host.nix];
            specialArgs = {inherit pkgs lib;};
          }).options.aos.terrane;
      in
        !options.exposures.type.check "[[expose]]" && !(options ? extraConfig);
    }
    {
      name = "duplicate-exposure-refused";
      pass = rejected {
        aos.terrane.sdkOutputRoots = ["/srv"];
        aos.terrane.exposures =
          builtins.genList (_: {
            id = "duplicate";
            view = "refs/heads/main";
            surface = "sdk";
            at = "/srv/sdk";
            token = "anonymous:refs/heads/main:read";
          })
          2;
      };
    }
    {
      name = "rendered-unit-confinement";
      pass = builtins.all (role: let text = enabled.system.build.systemdUnitBodies."terrane-${role}.service".text; in lib.hasInfix "CapabilityBoundingSet=" text && lib.hasInfix "NoNewPrivileges=true" text && lib.hasInfix "--role ${role}" text) roles;
    }
    {
      name = "publisher-state-custody";
      pass = builtins.elem "/var/lib/terrane/state/publication" (service "publish").ReadWritePaths && !(builtins.elem "/var/lib/terrane/state" (service "serve").ReadWritePaths) && lib.hasInfix "d /var/lib/terrane/state 0755 root root" enabled.environment.etc."tmpfiles.d/terrane.conf".text;
    }
    {
      name = "domain-root-traversal-custody";
      pass = let
        cfg = evaluate {
          aos.terrane.hostTier.path = "/srv/terrane-administrative";
          aos.terrane.hostTier.domains = {
            public.path = "/srv/terrane-public";
            "private:operator" = {
              path = "/srv/terrane-private";
              wipe = "none";
            };
            "tenant:operator".path = "/srv/terrane-tenant";
            "group:operator".path = "/srv/terrane-group";
          };
        };
        lines = lib.splitString "\n" cfg.environment.etc."tmpfiles.d/terrane.conf".text;
        rootLines = path: builtins.filter (line: lib.hasPrefix "d ${path} " line) lines;
        defaultRootLines = builtins.filter (line: lib.hasPrefix "d /var/lib/terrane " line) (lib.splitString "\n" enabled.environment.etc."tmpfiles.d/terrane.conf".text);
      in
        checksPass cfg
        # Exact singleton lists also reject duplicate declarations which could
        # restore a world-searchable mode after the protected declaration.
        && defaultRootLines == ["d /var/lib/terrane 0755 root root - -"]
        && rootLines "/srv/terrane-administrative" == ["d /srv/terrane-administrative 0755 root root - -"]
        && rootLines "/srv/terrane-public" == ["d /srv/terrane-public 0755 root root - -"]
        && builtins.all (name: rootLines "/srv/terrane-${name}" == ["d /srv/terrane-${name} 0750 root terrane-content - -"]) ["private" "tenant" "group"];
    }
    {
      name = "nonpublic-host-root-not-widened";
      pass = builtins.all (domain: let
        cfg = evaluate {
          aos.terrane.hostTier = {
            path = "/srv/terrane-domain";
            domains = {
              public.path = "/srv/terrane-public";
              "${domain}:operator" = {
                path = "/srv/terrane-domain";
                wipe = "none";
              };
            };
          };
        };
        lines = lib.splitString "\n" cfg.environment.etc."tmpfiles.d/terrane.conf".text;
        rootLines = builtins.filter (line: lib.hasPrefix "d /srv/terrane-domain " line) lines;
      in
        checksPass cfg && rootLines == ["d /srv/terrane-domain 0750 root terrane-content - -"])
      ["private" "tenant" "group"];
    }
    {
      name = "native-cache-rejects-unbounded-lower-policy";
      pass = builtins.all (lower:
        rejectedNative {
          aos.terrane.hostTier.domains.public.cache = cacheFixture // {inherit lower;};
        }) [
        (cacheFixture.lower // {budgetMs = 0;})
        (cacheFixture.lower // {budgetMs = 300001;})
        (cacheFixture.lower // {failureThreshold = 0;})
        (cacheFixture.lower // {failureThreshold = 1001;})
        (cacheFixture.lower // {probeIntervalMs = 0;})
        (cacheFixture.lower // {probeIntervalMs = 300001;})
      ];
    }
    {
      name = "native-cache-resources-rendered-exactly";
      pass =
        checksPass cached
        && builtins.all (word: lib.hasInfix word cachedFile) [
          "[host_tier.domains.public.cache]"
          "capacity_bytes = 25165824"
          "state_records = 64"
          "state_gid = 844"
          "metadata_sync_hold_bytes = 262144"
          "consumer_lease_seconds = 30"
          "[host_tier.domains.public.cache.lower]"
          "budget_ms = 10000"
          "failure_threshold = 3"
          "probe_interval_ms = 5000"
          "[host_tier.domains.public.cache.portable]"
          "max_files = 4096"
        ];
    }
    {
      name = "native-cache-omission-preserved";
      pass = !(lib.hasInfix "[host_tier.domains.public.cache]" nativeFile);
    }
    {
      name = "native-cache-surface-index-omission-preserved";
      pass = !(lib.hasInfix "surface_index" cachedFile);
    }
    {
      name = "native-cache-surface-index-rendered-exactly";
      pass = let
        cfg = evaluate (lib.recursiveUpdate nativeFixture {
          aos.terrane.hostTier.domains.public.cache = cacheFixture // {surfaceIndex = surfaceIndexFixture;};
        });
        text = cfg.environment.etc."terrane/terrane.toml".text;
      in
        checksPass cfg
        && builtins.all (word: lib.hasInfix word text) [
          "[host_tier.domains.public.cache.surface_index]"
          "max_entries = 64"
          "max_node_bytes = 131072"
          "max_index_bytes = 65536"
          "capacity_bytes = 1048576"
          "future_hold_bytes = 327680"
        ];
    }
    {
      name = "native-cache-surface-index-invalid-bounds-refused";
      pass = builtins.all (surfaceIndex:
        rejectedNative {
          aos.terrane.hostTier.domains.public.cache = cacheFixture // {inherit surfaceIndex;};
        }) [
        (builtins.removeAttrs surfaceIndexFixture ["maxEntries"])
        (surfaceIndexFixture // {maxEntries = 0;})
        (surfaceIndexFixture // {maxEntries = 4294967296;})
        (surfaceIndexFixture // {maxNodeBytes = 31;})
        (surfaceIndexFixture // {maxIndexBytes = 0;})
        (surfaceIndexFixture // {capacityBytes = 65535;})
        (surfaceIndexFixture // {capacityBytes = 25165825;})
        (surfaceIndexFixture // {futureHoldBytes = 327679;})
        (surfaceIndexFixture // {futureHoldBytes = 25165825;})
      ];
    }
    {
      name = "native-cache-incomplete-resources-refused";
      pass = rejectedNative {aos.terrane.hostTier.domains.public.cache = builtins.removeAttrs cacheFixture ["stateRecords"];};
    }
    {
      name = "native-cache-shared-state-group-refused";
      pass = rejectedNative {aos.terrane.hostTier.domains.public.cache = cacheFixture // {stateGid = 845;};};
    }
    {
      name = "native-cache-unfunded-repair-refused";
      pass = rejectedNative {
        aos.terrane.hostTier.domains.public.cache =
          cacheFixture
          // {
            indexRepair = {
              maxIndexBytes = 65536;
              futureHoldBytes = 262144;
            };
          };
      };
    }
  ];
  maintenanceAssertions = import ./module-maintenance-eval.nix {
    inherit lib evaluate nativeFixture cacheFixture surfaceIndexFixture checksPass;
  };
  sdkOutputAssertions = import ./module-sdk-output-eval.nix {
    inherit lib evaluate checksPass localFixture;
  };
  allAssertions = assertions ++ extraAssertions ++ maintenanceAssertions ++ sdkOutputAssertions;
  failures = map (check: check.name) (builtins.filter (check: !check.pass) allAssertions);
  verified =
    if failures == []
    then
      builtins.toJSON {
        scope = "declarative module evaluation; no kernel runtime claims";
        checks = map (check: check.name) allAssertions;
      }
    else throw "Terrane module evaluation failed: ${builtins.concatStringsSep ", " failures}";
in
  pkgs.mkDerivation {
    pname = "terrane-module-eval";
    version = "0.1.0";
    src = null;
    report = verified;
    passAsFile = ["report"];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          cp "$reportPath" "$out/result.json"
        '';
      }
    ];
  }
