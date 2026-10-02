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
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.system;
  releaseOsMetadata = lib.optionalString config.aos.release.enabled (
    lib.concatStringsSep "\n" [
      "AOS_RELEASE_TIER=${config.aos.release.tier}"
      "AOS_REGISTRY=${config.aos.release.registry}"
      "AOS_CHANNEL=${config.aos.release.channel}"
      "AOS_REGISTRY_ROOT_EPOCH=${toString config.aos.release.rootEpoch}"
    ]
    + "\n"
  );
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/data/_glibc-locales/module.nix];

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

    packageServicePolicyAbi = lib.mkOption {
      type = lib.types.int;
      default = 2;
      readOnly = true;
      apply = value:
        if value == 2
        then 2
        else throw "aos.system.packageServicePolicyAbi is an immutable image capability";
      description = ''
        Image capability for authenticated service policy drop-ins, retained
        build-identity removal checks, reserved Nix IDs, login fragments, and
        declared package child slices for independently recoverable resources.
      '';
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

  config = lib.mkMerge [
    {
      aos.packages.aos-runtime-checks = {
        package = pkgs.aos-runtime-checks;
        enable = true;
      };
    }
    {
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
            name = "kernel-version";
            description = "Kernel version matches the selected kernel";
            script = ''
              actual_kernel = vm.succeed("uname -r").strip()
              expected_kernel = "${config.system.build.kernel.version}"
              assert actual_kernel == expected_kernel, \
                  f"expected kernel {expected_kernel}, got {actual_kernel}"
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
          AOS_PACKAGE_MODULE_LIBRARY=${lib.packageModuleLibrary}
          ${releaseOsMetadata}
        '';
      };

      # /etc/hostname — static hostname file.
      # systemd-hostnamed reads this on boot.
      environment.etc."hostname" = {
        text = config.aos.networking.hostName + "\n";
      };

      environment.systemPackages = [pkgs.glibc-tools] ++ cfg.localePackages;
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
    }
  ];
}
