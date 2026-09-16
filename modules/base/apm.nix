##! modules/base/apm.nix — Package manager in every base image
##!
##! Ships the consumer-facing `apm` output on every AOS image and pre-creates
##! its config directory so first-use
##! commands like `apm registry add` don't have to mkdir their parent
##! under a read-only /. Loaded unconditionally by
##! `modules/default.nix`.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.apm.installAtBoot;
  registryRenderer = import ./_apm-registry-renderer.nix {inherit lib;};
  inherit (registryRenderer) registryToml trustedKeys trustedSbCerts;

  toml = lib.formats.toml {inherit lib pkgs;};

  packageNameRegex = "[A-Za-z0-9][A-Za-z0-9+._=-]*";
  packageNameType = lib.types.strMatching packageNameRegex;
  desiredConfigType = lib.types.attrsOf (lib.types.attrsOf (lib.types.attrsOf toml.type));
  rolloutDrain = config.aos.config.artifacts.aos-rollout-drain;
  rolloutHealth = config.aos.config.artifacts.aos-rollout-health;
  desiredToml = toml.toTOML ({
      packages = cfg.packages;
    }
    // lib.optionalAttrs (cfg.config != {}) {
      config = cfg.config;
    });

  registries = config.aos.apm.registries;

  # Files baked into the image /etc when install-at-boot is enabled. The
  # image-bootstrap reconciler consumes these only when no host-eval manifest
  # exists; dynamic host configuration is owned exclusively by the
  # unit graph.
  installAtBootEtc = lib.optionalAttrs cfg.enable (
    {
      "aos/packages.d/desired.toml" = {
        text = desiredToml;
        mode = "0600";
      };
    }
    // lib.optionalAttrs cfg.includeRegistries (
      lib.listToAttrs (lib.concatLists (lib.mapAttrsToList (
          name: registry:
            [
              {
                name = "apm/registries.d/${name}.toml";
                value = {
                  text = registryToml name registry;
                  mode = "0644";
                };
              }
              {
                name = "apm/trusted-keys.d/${name}.pub";
                value = {
                  text = trustedKeys registry;
                  mode = "0644";
                };
              }
            ]
            ++ lib.optionals (registry.sbDbCerts != []) [
              {
                name = "apm/trusted-sb-certs.d/${name}.pem";
                value = {
                  text = trustedSbCerts registry;
                  mode = "0644";
                };
              }
            ]
        )
        registries))
    )
  );
in {
  options.aos.apm.drainScript = lib.mkOption {
    type = lib.types.nullOr lib.types.path;
    default = null;
    description = ''
      Executable hook invoked before an A/B system transition requested with
      `--drain --reboot`. The hook is linked into the immutable system
      toplevel and must return successfully before the reboot is queued.
    '';
  };

  options.aos.apm.healthScript = lib.mkOption {
    type = lib.types.nullOr lib.types.path;
    default = null;
    description = ''
      Executable hook used by an ability-qualified A/B rollout after the
      candidate configuration activates. Exit status zero admits the candidate,
      status one requests fallback, and any other status is indeterminate.
    '';
  };

  options.aos.apm.installAtBoot = {
    enable = lib.mkEnableOption "apm desired-package reconciliation at first boot";

    packages = lib.mkOption {
      type = lib.types.listOf packageNameType;
      default = [];
      description = ''
        Explicit APM package roots to place in
        `/etc/aos/packages.d/desired.toml`.
      '';
    };

    config = lib.mkOption {
      type = desiredConfigType;
      default = {};
      description = ''
        Package-scoped non-secret config to render under
        `config.<package>.<artifact>` in `desired.toml`.
      '';
    };

    includeRegistries = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Bake `aos.apm.registries` into `/etc/apm/registries.d` and the
        trust-anchor files.
      '';
    };

    etc = lib.mkOption {
      type = lib.types.attrsOf lib.types.attrs;
      readOnly = true;
      description = ''
        The `environment.etc` entries baked into the image when install-at-boot
        is enabled: `desired.toml` and, when `includeRegistries` is set, the
        matching registry config + trust anchors.
      '';
    };
  };

  config = {
    assertions =
      builtins.map (name: {
        assertion = builtins.match packageNameRegex name != null;
        message = ''
          aos.apm.installAtBoot.config.${name}: package config keys must
          be valid APM package names (${packageNameRegex}).
        '';
      })
      (builtins.attrNames cfg.config);

    aos.apm.installAtBoot.etc = installAtBootEtc;
    aos.packageRuntime.packageProfile = {
      enable = cfg.enable;
      desiredText = desiredToml;
    };
    aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = cfg.enable;

    # These image-fixed helpers must be built in stage 1. The on-host stage-2
    # evaluator receives only their frozen paths and has no script builder.
    aos.config._artifactSources = {
      aos-rollout-drain =
        if config.aos.config.frozenArtifacts ? "aos-rollout-drain"
        then null
        else
          pkgs.writeShellScriptBin "aos-rollout-drain" ''
            set -eu

            hook=/run/current-system/drain
            if [ ! -x "$hook" ]; then
              echo "aos-rollout-drain: the current system has no configured drain hook" >&2
              exit 1
            fi
            exec "$hook"
          '';
      aos-rollout-health =
        if config.aos.config.frozenArtifacts ? "aos-rollout-health"
        then null
        else
          pkgs.writeShellScriptBin "aos-rollout-health" ''
            set -eu

            hook=/run/current-system/health
            if [ ! -x "$hook" ]; then
              echo "aos-rollout-health: the current system has no configured health hook" >&2
              exit 2
            fi
            if "$hook"; then
              exit 0
            else
              status=$?
            fi
            if [ "$status" -eq 1 ]; then
              exit 1
            fi
            echo "aos-rollout-health: health hook failed without a conclusive result" >&2
            exit 2
          '';
    };

    # The consumer CLI is the only AOS command surface on the system PATH.
    # Repository construction (`aos`) and registry authoring (`apr`) remain
    # host tools; private activation helpers are referenced by absolute path.
    environment.systemPackages = [pkgs.aos.apm rolloutDrain rolloutHealth];

    # install-at-boot's baked /etc (desired.toml + registry config) plus the
    # tmpfiles config. `apm registry add` writes
    # `~/.config/apm/registries.d/<name>.toml`; the root-owned tree is baked by
    # lib/build/rootfs.nix because /root lives on the read-only rootfs, so
    # tmpfiles only manages writable runtime paths.
    environment.etc =
      installAtBootEtc
      // {
        "tmpfiles.d/aos-apm.conf".text = ''
          # /etc/tmpfiles.d/aos-apm.conf
          # Generated by modules/base/apm.nix — do not edit manually.
          d  /etc/aos/packages.d                 0755 root root - -
          d  /run/aos-attest                     0700 root root - -
          d  /var/lib/apm                        0755 root root - -
          d  /var/lib/apm/config                 0755 root root - -
          d  /var/lib/apm/config/registries.d    0755 root root - -
        '';
      };

    system.checks.apm = {
      description = "apm base-image smoke checks";
      checks = [
        {
          name = "apm-help";
          description = "the independent apm parser exposes package-consumer help";
          # Exercise the exact packaged wrapper installed into the image.
          script = ''
            vm.succeed("${pkgs.aos.apm}/bin/apm --help")
          '';
        }
        {
          name = "registries-dir";
          description = "the apm config directory forest was pre-created";
          script = ''
            vm.succeed("test -d /root/.config/apm/registries.d")
            vm.succeed("test -d /var/lib/apm/config/registries.d")
          '';
        }
      ];
    };
  };
}
