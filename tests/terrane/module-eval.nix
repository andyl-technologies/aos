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
  extraAssertions = [
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
