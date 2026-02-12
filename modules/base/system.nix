# modules/base/system.nix — Core system identity module
#
# Defines the fundamental identity of the AOS installation: name, version,
# variant, locale, and timezone. Generates /etc/os-release and configures
# systemd locale and timezone settings.
#
# Absorbed TOML config values:
#   [system] name, version, variant, state_version
#   [locale] lang, timezone

{
  config,
  pkgs,
  lib,
  ...
}:

let
  cfg = config.aos.system;
in
{
  options.aos.system = {
    name = lib.mkOption {
      type = lib.types.str;
      default = "aos";
      description = "Operating system name used in os-release and branding.";
    };

    version = lib.mkOption {
      type = lib.types.str;
      default = "0.1.0";
      description = "AOS release version string.";
    };

    variant = lib.mkOption {
      type = lib.types.str;
      default = "base";
      description = ''
        System variant name. Common values: "base", "k8s-worker",
        "k8s-control-plane", "server".
      '';
    };

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

    locale = lib.mkOption {
      type = lib.types.str;
      default = "C.UTF-8";
      description = "System locale (LANG environment variable).";
    };

    timezone = lib.mkOption {
      type = lib.types.str;
      default = "UTC";
      description = "System timezone (e.g. UTC, America/New_York).";
    };
  };

  config = {
    # /etc/os-release — standard freedesktop.org OS identification file.
    # Consumed by systemd, container runtimes, and monitoring tools.
    environment.etc."os-release" = {
      text = ''
        NAME="${cfg.name}"
        ID=${lib.toLower cfg.name}
        VERSION="${cfg.version}"
        VERSION_ID=${cfg.version}
        PRETTY_NAME="${cfg.name} ${cfg.version} (${cfg.variant})"
        VARIANT="${cfg.variant}"
        VARIANT_ID=${lib.toLower cfg.variant}
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
