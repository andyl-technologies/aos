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

  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };
  toml = lib.formats.toml {inherit lib pkgs;};

  packageNameRegex = "[A-Za-z0-9][A-Za-z0-9+._=-]*";
  packageNameType = lib.types.strMatching packageNameRegex;
  credentialNameRegex = "[A-Za-z0-9_.-]+";
  credentialNameType = lib.types.strMatching credentialNameRegex;
  desiredConfigType = lib.types.attrsOf (lib.types.attrsOf (lib.types.attrsOf toml.type));
  desiredCredentialsType = lib.types.attrsOf (lib.types.attrsOf lib.types.str);
  desiredSystemCredentialsType = lib.types.attrsOf (lib.types.attrsOf credentialNameType);

  uriEncode =
    builtins.replaceStrings
    ["%" "\n" "\r" "\t" " " "!" "\"" "#" "$" "&" "'" "(" ")" "*" "+" "," "/" ":" ";" "<" "=" ">" "?" "@" "[" "\\" "]" "^" "`" "{" "|" "}"]
    ["%25" "%0A" "%0D" "%09" "%20" "%21" "%22" "%23" "%24" "%26" "%27" "%28" "%29" "%2A" "%2B" "%2C" "%2F" "%3A" "%3B" "%3C" "%3D" "%3E" "%3F" "%40" "%5B" "%5C" "%5D" "%5E" "%60" "%7B" "%7C" "%7D"];
  dataUrl = content: let
    encoded = uriEncode content;
  in
    if builtins.match "[A-Za-z0-9._~%+-]*" encoded == null
    then
      throw ''
        aos.apm.installAtBoot cannot encode non-ASCII or control
        characters in generated Ignition data URLs.
      ''
    else "data:,${encoded}";

  systemCredentialEntries =
    lib.mapAttrs
    (_package: credentials:
      lib.mapAttrs
      (_name: systemCredential: {
        system-credential = systemCredential;
      })
      credentials)
    cfg.systemCredentials;
  desiredCredentials = lib.recursiveUpdate cfg.credentials systemCredentialEntries;
  credentialPackages =
    lib.unique ((builtins.attrNames cfg.credentials) ++ (builtins.attrNames cfg.systemCredentials));
  credentialConflicts =
    lib.concatMap (
      package: let
        plaintextNames = builtins.attrNames (cfg.credentials.${package} or {});
        systemNames = builtins.attrNames (cfg.systemCredentials.${package} or {});
        overlaps = builtins.filter (name: builtins.elem name systemNames) plaintextNames;
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
    ++ lib.optionals cfg.enable ["aos-install-packages.service"];

  desiredToml = toml.toTOML ({
      packages = cfg.packages;
    }
    // lib.optionalAttrs (cfg.config != {}) {
      config = cfg.config;
    }
    // lib.optionalAttrs (desiredCredentials != {}) {
      credentials = desiredCredentials;
    });

  desiredFile = {
    path = "/etc/aos/packages.d/desired.toml";
    mode = 384; # 0600
    overwrite = true;
    contents.source = dataUrl desiredToml;
  };

  registries = config.aos.apm.registries;
  hasSbCerts = builtins.any (registry: registry.sbDbCerts != []) (builtins.attrValues registries);
  registryDirs =
    [
      {
        path = "/etc/apm";
        mode = 493; # 0755
        overwrite = true;
      }
      {
        path = "/etc/apm/registries.d";
        mode = 493; # 0755
        overwrite = true;
      }
      {
        path = "/etc/apm/trusted-keys.d";
        mode = 493; # 0755
        overwrite = true;
      }
    ]
    ++ lib.optionals hasSbCerts [
      {
        path = "/etc/apm/trusted-sb-certs.d";
        mode = 493; # 0755
        overwrite = true;
      }
    ];
  registryFiles =
    lib.concatLists
    (lib.mapAttrsToList (
        name: registry:
          [
            {
              path = "/etc/apm/registries.d/${name}.toml";
              mode = 420; # 0644
              overwrite = true;
              contents.source = dataUrl (registryToml name registry);
            }
            {
              path = "/etc/apm/trusted-keys.d/${name}.pub";
              mode = 420; # 0644
              overwrite = true;
              contents.source = dataUrl (trustedKeys registry);
            }
          ]
          ++ lib.optionals (registry.sbDbCerts != []) [
            {
              path = "/etc/apm/trusted-sb-certs.d/${name}.pem";
              mode = 420; # 0644
              overwrite = true;
              contents.source = dataUrl (trustedSbCerts registry);
            }
          ]
      )
      registries);

  installAtBootIgnitionConfig =
    if cfg.enable
    then {
      storage = {
        directories =
          [
            {
              path = "/etc/aos";
              mode = 493; # 0755
              overwrite = true;
            }
            {
              path = "/etc/aos/packages.d";
              mode = 493; # 0755
              overwrite = true;
            }
          ]
          ++ lib.optionals cfg.includeRegistries registryDirs;
        files =
          [desiredFile]
          ++ lib.optionals cfg.includeRegistries registryFiles;
      };
    }
    else {};
in {
  options.aos.apm.installAtBoot = {
    enable = lib.mkEnableOption "Ignition-authored apm desired-package reconciliation";

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
        Package-scoped credential plaintext to render under
        `credentials.<package>` in `desired.toml` for first-boot
        provisioning into signed package-declared systemd credstore
        sources.
      '';
    };

    systemCredentials = lib.mkOption {
      type = desiredSystemCredentialsType;
      default = {};
      description = ''
        Package-scoped system credential references to render under
        `credentials.<package>` in `desired.toml`. `apm` reads plaintext from
        `/run/credentials/@system/<name>` at first boot instead of embedding it
        in the desired file.
      '';
    };

    includeRegistries = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Include `aos.apm.registries` as Ignition-written
        `/etc/apm/registries.d` and trust-anchor files.
      '';
    };

    ignitionConfig = lib.mkOption {
      type = ignitionFormat.type;
      readOnly = true;
      description = ''
        Ignition fragment that writes `desired.toml` and, when enabled,
        matching registry configuration via `storage.files`.
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
          assertion = credentialConflicts == [];
          message = ''
            aos.apm.installAtBoot credentials and systemCredentials must not
            both define the same package credential(s):
            ${builtins.concatStringsSep ", " credentialConflicts}.
          '';
        }
      ];

    aos.apm.installAtBoot.ignitionConfig = installAtBootIgnitionConfig;

    # `apm`'s registry/update and runtime attach paths rely on the hermetic
    # wrapper in `pkgs/tools/aos/aos.nix` for shell-out tools such as git, tar,
    # nix, and systemctl. Keeping `pkgs.aos` in the base image makes those
    # tools available through the wrapper without relying on the host PATH.
    environment.systemPackages = [pkgs.aos pkgs.tar];

    # `apm registry add` writes `~/.config/apm/registries.d/<name>.toml`
    # (crates/aos-package/src/lib.rs:1273; mkdir at :1245). Pre-
    # creating the path keeps first-use clean under a read-only /;
    # non-root users mkdir under their own $HOME on first use.
    environment.etc."tmpfiles.d/aos-apm.conf".text = ''
      # /etc/tmpfiles.d/aos-apm.conf
      # Generated by modules/base/apm.nix — do not edit manually.
      d  /root/.config                       0700 root root - -
      d  /root/.config/apm                   0755 root root - -
      d  /root/.config/apm/registries.d      0755 root root - -
      d  /etc/aos/packages.d                 0755 root root - -
      d  /run/aos-attest                     0700 root root - -
    '';

    systemd.services.aos-attest = {
      description = "Produce AOS package attestation quote";
      requires = packageAttestationReadinessUnits;
      after = [
        "aos-seed-baked-packages.service"
        "aos-install-packages.service"
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

    systemd.services.aos-install-packages = {
      description = "Reconcile AOS desired packages";
      wantedBy = ["multi-user.target"];
      before = [
        "aos-preset.service"
        "multi-user.target"
      ];
      after = [
        "ignition-files.service"
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
        AOS_EXPOSE_START_NO_WAIT=1 ${pkgs.aos}/bin/apm install --system --from /etc/aos/packages.d/desired.toml --yes
      '';
    };

    system.checks.apm = {
      description = "apm/apr base-image smoke checks";
      checks = [
        {
          name = "apm-version";
          description = "apm --version exits 0 (argv[0] dispatch via the store-path bin)";
          # Invoke via the absolute store path, not via /usr/bin/apm.
          # The rootfs symlink-farm (lib/build/rootfs.nix:83-99) globs
          # `${pkg}/bin/*` which omits dotfiles, so the
          # `.apm-unwrapped` companion never appears next to the
          # PATH-installed `apm` symlink — the wrapper's
          # `exec "$(dirname "$0")/.apm-unwrapped"` then fails. Using
          # the store path means `dirname "$0"` resolves to the bin
          # dir that *does* contain the unwrapped binary.
          script = ''
            vm.succeed("${pkgs.aos}/bin/apm --version")
          '';
        }
        {
          name = "registries-dir";
          description = "the apm config directory tree was pre-created";
          script = ''
            vm.succeed("test -d /root/.config/apm/registries.d")
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
