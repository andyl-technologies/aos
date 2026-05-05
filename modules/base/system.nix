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

  # The helper functions referenced by `script` (`run_in_guest`,
  # `assert_success`, `assert_output_contains`) are defined in
  # `lib/testing/assertions.nix` and injected into the host-side
  # shell that runs each check against the VM's guest agent.
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
          Shell fragment run on the host against the guest agent.
          See `lib/testing/assertions.nix` for the helper vocabulary
          (`run_in_guest`, `assert_success`,
          `assert_output_contains`).
        '';
      };
    };
  };

  # Fully-typed Ignition v3.6 schema. `allowStorageHardware = false`
  # omits `storage.{disks,filesystems,raid,luks}` so test-harness
  # configs that try to manage partitioning fail at eval with a
  # readable "option not declared" error — those paths belong to the
  # AOS image, not to first-boot metadata. Production / standalone
  # callers that want the full schema can import
  # `lib/formats/ignition.nix` directly with `allowStorageHardware = true`.
  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };
  ignitionConfigType = ignitionFormat.type;

  instanceMetadataType = lib.types.submodule {
    options = {
      format = lib.mkOption {
        type = lib.types.enum ["ignition"];
        default = "ignition";
        description = "Provisioner that will consume the metadata.";
      };
      config = lib.mkOption {
        type = ignitionConfigType;
        description = ''
          The ignition config as a Nix attrset. The test harness
          serialises it to JSON, packs it into an ISO9660 image
          (volume label `aos-metadata`), and attaches it to the VM;
          `aos-platform-detect.service` mounts it and points ignition
          at the file via `IGNITION_CONFIG_FILE`.
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
      instanceMetadata = lib.mkOption {
        type = lib.types.nullOr instanceMetadataType;
        default = null;
        description = ''
          Optional first-boot provisioning payload. When set, the
          test harness attaches a second virtio-blk device carrying
          this JSON. Ignition runs on every test boot (metadata or
          not), but only consumes a config when this option is set.
        '';
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
          description = "os-release contains ANDYL OS";
          script = ''
            assert_output_contains "cat /etc/os-release" "ANDYL OS" \
              "os-release contains ANDYL OS"
          '';
        }
        {
          name = "hostname";
          description = "Hostname is set";
          script = ''
            assert_success "test -f /etc/hostname" \
              "/etc/hostname exists"
          '';
        }
        {
          name = "systemd-running";
          description = "systemd reached multi-user.target";
          script = ''
            assert_success "systemctl is-active multi-user.target" \
              "systemd reached multi-user.target"
          '';
        }
        {
          name = "kernel-version";
          description = "Kernel version is 6.18.x";
          script = ''
            assert_output_contains "uname -r" "6.18" \
              "kernel version is 6.18.x"
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
            assert_success "test -d /run/systemd/system" \
              "systemd runtime directory exists"
          '';
        }
        {
          name = "timers";
          description = "systemd timers are functional";
          script = ''
            assert_success "systemctl list-timers --no-pager" \
              "systemd timers are functional"
          '';
        }
        {
          name = "list-services";
          description = "systemctl can list services";
          script = ''
            assert_success "systemctl list-units --type=service --no-pager" \
              "systemctl can list services"
          '';
        }
        {
          name = "journal";
          description = "journalctl can read system journal";
          script = ''
            assert_success "journalctl --no-pager -n 5" \
              "journalctl can read system journal"
          '';
        }
        {
          name = "etc-writable";
          description = "/etc is writable for updates";
          script = ''
            assert_success "touch /etc/test-write && rm /etc/test-write" \
              "/etc is writable for updates"
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
    # This is the standard mechanism for glibc and systemd.
    environment.etc."localtime" = {
      source = "/usr/share/zoneinfo/${cfg.timezone}";
    };

    # Write the timezone name for tools that read it as a string.
    environment.etc."timezone" = {
      text = cfg.timezone + "\n";
    };
  };
}
