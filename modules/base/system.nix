##! modules/base/system.nix — Core system identity module
##!
##! Defines the fundamental identity of the AOS installation: name, version,
##! locale, and timezone. Generates /etc/os-release and configures
##! systemd locale and timezone settings.
##!
##! Absorbed TOML config values:
##!   [system] name, version, state_version
##!   [locale] lang, timezone
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.system;

  # `script` is Python source — run by the AOS test driver
  # (pkgs/tools/aos/aos-test-driver) against the guest agent. Each
  # check sees the system under test as the `vm` module global; use
  # `vm.succeed("...")`, `vm.fail("...")`,
  # `vm.wait_until_succeeds("...", timeout=60)`, etc. — see
  # `pkgs/tools/aos/aos-test-driver/aos_test_driver/machine.py` for
  # the full Machine API.
  checkType = lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Check identifier; used in log banners as <group>/<name>.";
      };
      description = lib.mkOption {
        type = lib.types.str;
        description = "Human-readable purpose of the check.";
      };
      script = lib.mkOption {
        type = lib.types.lines;
        description = ''
          Python fragment run by the AOS test driver against the
          guest agent. The VM under test is the `vm` module global.
          See `pkgs/tools/aos/aos-test-driver/aos_test_driver/machine.py`
          for the Machine API (`succeed`, `fail`,
          `wait_until_succeeds`, `wait_for_unit`, `wait_for_file`,
          `execute`).
        '';
      };
    };
  };

  checkSpecType = lib.types.submodule ({name, ...}: {
    options = {
      description = lib.mkOption {
        type = lib.types.str;
        default = name;
        description = "Description shown in the test log banner.";
      };
      checks = lib.mkOption {
        type = lib.types.listOf checkType;
        description = "Flat list of checks run inside one VM.";
      };
    };
  });
in {
  options.system.checks = lib.mkOption {
    type = lib.types.attrsOf checkSpecType;
    default = {};
    description = ''
      VM checks contributed by modules, keyed by check-group name.
      Each entry produces one test derivation at
      `system.build.checks.<name>`.
    '';
  };

  options.aos.system = {
    ## Operating system name used in os-release and branding.
    name = lib.mkOption {
      type = lib.types.str;
      default = "aos";
      description = "Operating system name used in os-release and branding.";
    };

    ## AOS release version string.
    version = lib.mkOption {
      type = lib.types.str;
      default = "0.1.0";
      description = "AOS release version string.";
    };

    ## State version for forward-compatible migrations.
    stateVersion = lib.mkOption {
      type = lib.types.str;
      default = "1";
      description = ''
        State version for forward-compatible migrations. Changing this
        value signals that state-migration scripts should run on upgrade.
        Do not change this on a running system without understanding the
        migration implications.
      '';
    };

    ## Shared-option-schema ABI integer used to validate configuration generations.
    ##
    ## A monotonic integer identifying the base-lib option schema this image
    ## ships. It is written to `/etc/os-release` as `AOS_MODULE_ABI` (and so
    ## into the UKI `.osrel` section measured into PCR 11), and the on-host
    ## resolver reads it to gate every config module's `module_abi_compat`
    ## band before evaluation. Orthogonal to `stateVersion` (a /var
    ## state-migration trigger) — the two gate different artifacts at
    ## different phases and need not coincide.
    moduleAbi = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = ''
        Shared-option-schema ABI integer for this image. Emitted as
        `AOS_MODULE_ABI` in /etc/os-release (and the measured UKI .osrel),
        used by the on-host resolver as the pre-eval admission gate for
        config modules. Bump on a breaking change to the shared option
        schema. Independent of `stateVersion`.
      '';
    };

    configInputAbi = lib.mkOption {
      type = lib.types.int;
      default = 2;
      readOnly = true;
      description = ''
        Persistent evaluator-input ABI. Version 2 binds a separately
        authenticated runtime module set and generation compare-and-swap.
      '';
    };

    ## System locale (LANG environment variable).
    ##
    ## # Examples
    ## ```nix
    ## aos.system.locale = "en_US.UTF-8";
    ## ```
    locale = lib.mkOption {
      type = lib.types.str;
      default = "C.UTF-8";
      description = "System locale (LANG environment variable).";
    };

    ## System timezone (e.g. UTC, America/New_York).
    ##
    ## # Examples
    ## ```nix
    ## aos.system.timezone = "America/New_York";
    ## ```
    timezone = lib.mkOption {
      type = lib.types.str;
      default = "UTC";
      description = "System timezone (e.g. UTC, America/New_York).";
    };
  };

  config = {
    system.checks.boot-basics = {
      description = "Core boot verification";
      checks = [
        {
          name = "os-release";
          description = "os-release identifies the configured OS name + version";
          script = ''
            osrel = vm.succeed("cat /etc/os-release")
            assert 'NAME="${cfg.name}"' in osrel, osrel
            assert "VERSION_ID=${cfg.version}" in osrel, osrel
          '';
        }
        {
          name = "hostname";
          description = "Hostname is set";
          script = ''
            vm.succeed("test -f /etc/hostname")
          '';
        }
        {
          name = "systemd-running";
          description = "systemd reached multi-user.target";
          script = ''
            vm.succeed("systemctl is-active multi-user.target")
          '';
        }
        {
          name = "kernel-version";
          description = "Kernel version is 6.18.x";
          script = ''
            assert "6.18" in vm.succeed("uname -r")
          '';
        }
      ];
    };

    system.checks.systemd-basics = {
      description = "systemd service infrastructure checks";
      checks = [
        {
          name = "runtime-dir";
          description = "systemd runtime directory exists";
          script = ''
            vm.succeed("test -d /run/systemd/system")
          '';
        }
        {
          name = "timers";
          description = "systemd timers are functional";
          script = ''
            vm.succeed("systemctl list-timers --no-pager")
          '';
        }
        {
          name = "list-services";
          description = "systemctl can list services";
          script = ''
            vm.succeed("systemctl list-units --type=service --no-pager")
          '';
        }
        {
          name = "journal";
          description = "journalctl can read system journal";
          script = ''
            vm.succeed("journalctl --no-pager -n 5")
          '';
        }
        {
          name = "etc-writable";
          description = "/etc is writable for updates";
          script = ''
            vm.succeed("touch /etc/test-write && rm /etc/test-write")
          '';
        }
      ];
    };

    # /etc/os-release — standard freedesktop.org OS identification file.
    # Consumed by systemd, container runtimes, and monitoring tools.
    environment.etc."os-release" = {
      text = ''
        NAME="${cfg.name}"
        ID=${lib.toLower cfg.name}
        VERSION="${cfg.version}"
        VERSION_ID=${cfg.version}
        PRETTY_NAME="${cfg.name} ${cfg.version}"
        HOME_URL="https://aos.dev"
        BUG_REPORT_URL="https://aos.dev/issues"
        AOS_STATE_VERSION=${cfg.stateVersion}
        AOS_MODULE_ABI=${toString cfg.moduleAbi}
        AOS_CONFIG_INPUT_ABI=${toString cfg.configInputAbi}
        AOS_BASELIB_DIGEST=sha256:${builtins.hashString "sha256" (toString config.aos.config.evalAtBoot.baseLib)}
        ${lib.optionalString config.aos.release.enabled ''AOS_RELEASE_TIER=${config.aos.release.tier}
        AOS_REGISTRY=${config.aos.release.registry}
        AOS_CHANNEL=${config.aos.release.channel}
        AOS_REGISTRY_ROOT_EPOCH=${toString config.aos.release.rootEpoch}''}
      '';
    };

    # /etc/hostname — static hostname file.
    # systemd-hostnamed reads this on boot.
    environment.etc."hostname" = {
      text = config.aos.networking.hostName + "\n";
    };

    # Locale configuration via systemd's locale.conf.
    # systemd reads /etc/locale.conf and exports LANG to all services.
    environment.etc."locale.conf" = {
      text = ''
        LANG=${cfg.locale}
      '';
    };

    # Timezone: symlink /etc/localtime to the zoneinfo database.
    # This is the standard mechanism for glibc and systemd. Source is
    # the hermetic `pkgs.tzdata` package, not the host's
    # `/usr/share/zoneinfo` (which is unspecified inside the Nix
    # sandbox and would break the composefs dump script's
    # `os.path.isdir(source)` probe).
    environment.etc."localtime" = {
      source = "${pkgs.tzdata}/share/zoneinfo/${cfg.timezone}";
    };

    # Write the timezone name for tools that read it as a string.
    environment.etc."timezone" = {
      text = cfg.timezone + "\n";
    };
  };
}
