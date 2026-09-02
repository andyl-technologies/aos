##! modules/base/apm.nix — Package manager in every base image
##!
##! Ships `pkgs.aos` (the `aos`, `apm`, and `apr` binaries) on every
##! AOS image, and pre-creates the apm config directory so first-use
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
  credentialNameRegex = lib.serviceTypes.credentialNameRegex;
  credentialNameType = lib.serviceTypes.credentialName;
  desiredConfigType = lib.types.attrsOf (lib.types.attrsOf (lib.types.attrsOf toml.type));
  secretRefType = lib.types.submodule ({name, ...}: {
    config._module.strict = true;
    options = {
      name = lib.mkOption {
        type = credentialNameType;
        default = name;
        readOnly = true;
        description = "The systemd credential handle.";
      };
      source = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "The credstore destination path; never credential bytes.";
      };
      encrypted = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether the material at the destination is systemd-encrypted.";
      };
      units = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Service units that consume the credential.";
      };
      ref = lib.mkOption {
        type = lib.serviceTypes.secretReference;
        description = "The opaque credential resolver reference.";
      };
    };
  });
  desiredCredentialsType = lib.types.attrsOf (lib.types.attrsOf secretRefType);
  desiredSystemCredentialsType = lib.types.attrsOf (lib.types.attrsOf credentialNameType);

  desiredSystemCredentialValues =
    lib.mapAttrs
    (_package: credentials:
      lib.mapAttrs
      (_name: systemCredential: {
        system-credential = systemCredential;
      })
      credentials)
    cfg.systemCredentials;
  credentialPackages =
    lib.unique ((builtins.attrNames cfg.credentials) ++ (builtins.attrNames cfg.systemCredentials));
  credentialConflicts =
    lib.concatMap (
      package: let
        referenceNames = builtins.attrNames (cfg.credentials.${package} or {});
        systemNames = builtins.attrNames (cfg.systemCredentials.${package} or {});
        overlaps = builtins.filter (name: builtins.elem name systemNames) referenceNames;
      in
        builtins.map (name: "${package}.${name}") overlaps
    )
    credentialPackages;
  exposedBundledPackages =
    lib.filterAttrs
    (_: package: package.bundle && (package.package ? expose))
    config.aos.packages;
  packageAttestationReadinessUnits =
    lib.optionals (exposedBundledPackages != {}) ["aos-seed-baked-packages.service"]
    ++ lib.optionals cfg.enable ["aos-install-baked-packages.service"];

  desiredToml = toml.toTOML ({
      packages = cfg.packages;
    }
    // lib.optionalAttrs (cfg.config != {}) {
      config = cfg.config;
    }
    // lib.optionalAttrs (desiredSystemCredentialValues != {}) {
      credentials = desiredSystemCredentialValues;
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

    credentials = lib.mkOption {
      type = desiredCredentialsType;
      default = {};
      description = ''
        Package-scoped opaque credential references. Each reference contains
        only a handle, credstore destination, encryption policy, consuming
        units, and resolver discriminator. There is deliberately no plaintext
        `value` or `text` constructor.
      '';
    };

    systemCredentials = lib.mkOption {
      type = desiredSystemCredentialsType;
      default = {};
      description = ''
        Convenience mapping for platform system credentials. It projects to
        the same opaque reference schema as `credentials`, while the baked
        first-boot desired file tells `apm` to read bytes from
        `/run/credentials/@system/<name>` instead of embedding them.
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
      (builtins.attrNames cfg.config)
      ++ builtins.map (name: {
        assertion = builtins.match packageNameRegex name != null;
        message = ''
          aos.apm.installAtBoot.credentials.${name}: package credential keys
          must be valid APM package names (${packageNameRegex}).
        '';
      })
      (builtins.attrNames cfg.credentials)
      ++ builtins.map (name: {
        assertion = builtins.match packageNameRegex name != null;
        message = ''
          aos.apm.installAtBoot.systemCredentials.${name}: package credential
          keys must be valid APM package names (${packageNameRegex}).
        '';
      })
      (builtins.attrNames cfg.systemCredentials)
      ++ lib.concatLists (lib.mapAttrsToList (
          package: credentials:
            builtins.map (name: {
              assertion = builtins.match credentialNameRegex name != null;
              message = ''
                aos.apm.installAtBoot.credentials.${package}.${name}:
                credential names must match ${credentialNameRegex}.
              '';
            })
            (builtins.attrNames credentials)
        )
        cfg.credentials)
      ++ lib.concatLists (lib.mapAttrsToList (
          package: credentials:
            builtins.map (name: {
              assertion = builtins.match credentialNameRegex name != null;
              message = ''
                aos.apm.installAtBoot.systemCredentials.${package}.${name}:
                credential names must match ${credentialNameRegex}.
              '';
            })
            (builtins.attrNames credentials)
        )
        cfg.systemCredentials)
      ++ lib.concatLists (lib.mapAttrsToList (
          package: credentials:
            lib.mapAttrsToList (name: systemCredential: {
              assertion = builtins.match credentialNameRegex systemCredential != null;
              message = ''
                aos.apm.installAtBoot.systemCredentials.${package}.${name}:
                system credential names must match ${credentialNameRegex}.
              '';
            })
            credentials
        )
        cfg.systemCredentials)
      ++ [
        {
          # Force each strict secretRef submodule even when install-at-boot is
          # disabled. Otherwise an undeclared plaintext field can remain in an
          # unforced option thunk and escape the normal toplevel assertion
          # gate.
          assertion = builtins.deepSeq cfg.credentials true;
          message = "aos.apm.installAtBoot.credentials contains an invalid secretRef";
        }
        {
          assertion = credentialConflicts == [];
          message = ''
            aos.apm.installAtBoot credentials and systemCredentials must not
            both define the same package credential(s):
            ${builtins.concatStringsSep ", " credentialConflicts}.
          '';
        }
      ];

    aos.apm.installAtBoot.etc = installAtBootEtc;

    # The only package on the system PATH is the aos/apm/apr CLI. Everything
    # it shells out to (git-minimal, tar, nix, systemctl, …) rides in via its
    # runtimeDeps and the hermetic wrapper in `pkgs/tools/aos/aos.nix`, so it
    # need not be on PATH; all other tools are installed on demand with apm.
    environment.systemPackages = [pkgs.aos];

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
          d  /var/lib/apm/credential-transactions 0700 root root - -
          d  /var/lib/apm/config                 0755 root root - -
          d  /var/lib/apm/config/registries.d    0755 root root - -
        '';
      };

    systemd.services.aos-credential-recovery = {
      description = "Recover interrupted AOS credential publication";
      requiredBy = ["sysinit.target"];
      before = [
        "sysinit.target"
        "aos-eval.service"
        "multi-user.target"
      ];
      requires = ["local-fs.target"];
      after = ["local-fs.target"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        ${pkgs.aos}/bin/.aos-package-runtime-unwrapped recover-credential-transactions
      '';
    };

    systemd.services.aos-attest = {
      description = "Produce AOS package attestation quote";
      requires = packageAttestationReadinessUnits;
      after = [
        "aos-seed-baked-packages.service"
        "aos-install-baked-packages.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RuntimeDirectory = "aos-attest";
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "yes";
        StateDirectory = "aos-attest";
        StateDirectoryMode = "0700";
      };
      script = ''
        nonce_file=/run/aos-attest/nonce
        event_log=/run/log/aos-packages.cel
        output_dir=/var/lib/aos-attest/quote
        quote_json=/var/lib/aos-attest/quote.json
        quote_json_tmp=/var/lib/aos-attest/quote.json.tmp
        cleanup() {
          status=$?
          if ! ${pkgs.coreutils}/bin/rm -f -- "$nonce_file" "$quote_json_tmp"; then
            if [ "$status" -eq 0 ]; then
              status=1
            fi
          fi
          exit "$status"
        }
        trap cleanup EXIT
        # Package attestation produces a TPM quote over PCR 15. On TPM-less
        # machines the PCR measurement is skipped entirely (see
        # `measure_activated_packages` in crates/aos-package), so there is
        # nothing to quote — skip cleanly instead of failing. This keeps the
        # `apm upgrade --system` reconcile from failing on TPM-less hosts that
        # bundle an exposed package (the same "degrade gracefully" intent as the
        # measurement gate). `tpm2_tcti` probes these same device nodes.
        if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
          echo "no TPM device; skipping package attestation quote" >&2
          exit 0
        fi
        if [ ! -s "$nonce_file" ]; then
          echo "write verifier nonce hex to $nonce_file before starting aos-attest.service" >&2
          exit 2
        fi
        if [ ! -s "$event_log" ]; then
          echo "package attestation event log $event_log is not ready" >&2
          exit 3
        fi
        ${pkgs.coreutils}/bin/rm -rf -- "$output_dir"
        ${pkgs.coreutils}/bin/rm -f -- "$quote_json" "$quote_json_tmp"
        ${pkgs.aos}/bin/apm --json attest quote --nonce-file "$nonce_file" --output-dir "$output_dir" > "$quote_json_tmp"
        ${pkgs.coreutils}/bin/mv -f -- "$quote_json_tmp" "$quote_json"
      '';
    };

    systemd.services.aos-install-baked-packages = {
      description = "Reconcile image-baked AOS desired packages";
      wantedBy = ["multi-user.target"];
      before = [
        "aos-preset.service"
        "multi-user.target"
      ];
      after = [
        "aos-eval.service"
        "aos-config-seed.service"
        "aos-seed-profiles.service"
        "nix-overlay-setup.service"
      ];
      unitConfig.ConditionPathExists = "/etc/aos/packages.d/desired.toml";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        TimeoutStartSec = "2min";
      };
      script = ''
        # A host-eval manifest belongs to the unit graph. Never run a
        # second, monolithic reconciler over the same desired state.
        if [ -e /run/aos/manifest.json ]; then
          exit 0
        fi
        AOS_EXPOSE_START_NO_WAIT=1 ${pkgs.aos}/bin/apm install --system --from /etc/aos/packages.d/desired.toml --yes
      '';
    };

    system.checks.apm = {
      description = "apm/apr base-image smoke checks";
      checks = [
        {
          name = "apm-help";
          description = "apm --help exits 0 (argv[0] dispatch via the store-path bin)";
          # Invoke via the absolute store path, not via /usr/bin/apm.
          # The rootfs symlink-farm (lib/build/rootfs.nix:83-99) globs
          # `${pkg}/bin/*` which omits dotfiles, so the
          # `.apm-unwrapped` companion never appears next to the
          # PATH-installed `apm` symlink — the wrapper's
          # `exec "$(dirname "$0")/.apm-unwrapped"` then fails. Using
          # the store path means `dirname "$0"` resolves to the bin
          # dir that *does* contain the unwrapped binary.
          script = ''
            vm.succeed("${pkgs.aos}/bin/apm --help")
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
        {
          name = "apr-runs";
          description = "apr (registry surface, same binary) launches";
          # See apm-version above for the absolute-path rationale.
          script = ''
            vm.succeed("${pkgs.aos}/bin/apr --help")
          '';
        }
      ];
    };
  };
}
