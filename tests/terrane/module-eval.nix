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
      wipe = "zero";
    };
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
      name = "zero-preserved";
      pass = lib.hasInfix "wipe = \"zero\"" domainFile && lib.hasInfix "[host_tier.domains.\"private:example\"]" domainFile && lib.hasInfix "[[expose]]" domainFile;
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
      pass = builtins.elem "/var/lib/terrane/sealed" (service "publish").ReadWritePaths && builtins.all (role: !(builtins.elem "/var/lib/terrane/sealed" (service role).ReadWritePaths) && builtins.elem "/var/lib/terrane/sealed" (service role).InaccessiblePaths) ["serve" "realize" "gc"] && lib.hasInfix "d /var/lib/terrane 0755 root root" enabled.environment.etc."tmpfiles.d/terrane.conf".text && lib.hasInfix "d /var/lib/terrane/staging 0700 terrane-publish terrane-publish" enabled.environment.etc."tmpfiles.d/terrane.conf".text;
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
  extraAssertions = [
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
      pass = lib.hasInfix "wipe = \"zero\"" (evaluate {aos.terrane.hostTier.domains."private:default".path = "/var/lib/terrane-private";}).environment.etc."terrane/terrane.toml".text;
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
  ];
  failures = map (check: check.name) (builtins.filter (check: !check.pass) (assertions ++ extraAssertions));
  verified =
    if failures == []
    then
      builtins.toJSON {
        scope = "declarative module evaluation; no kernel runtime claims";
        checks = map (check: check.name) (assertions ++ extraAssertions);
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
