##! modules/services/registry-hub.nix — the AOS registry hub (RFC-0004)
##!
##! Runs `aos-hub serve` as a hardened systemd service so operators
##! deploy the multi-tenant registry management WebUI *with* AOS, per RFC-0004's
##! operations section. The hub is local-first and self-contained: a single
##! binary plus a sqlite database under `--root`, listening on `--listen`. It
##! shells out to nothing, so — unlike the registry *server* role — it needs no
##! PATH wiring.
##!
##! This contributes:
##!   * aos.users.users.aos-hub + group (a dedicated service account)
##!   * systemd.services.aos-hub running `aos-hub serve`
##!     under StateDirectory=aos-hub, with strict sandboxing
##!
##! Enable with `aos.registry-hub.enable = true`. The defaults bind localhost
##! (front a real instance behind a TLS-terminating reverse proxy and set
##! `externalUrl` to the public origin so setup snippets render correctly).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.registry-hub;
  externalArg =
    lib.optionalString (cfg.externalUrl != null)
    " --external-url ${lib.escapeShellArg cfg.externalUrl}";
in {
  options.aos.registry-hub = {
    enable = lib.mkEnableOption "the AOS registry management hub (aos-hub)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-hub;
      defaultText = lib.literalExpression "pkgs.aos-hub";
      description = "The aos-hub package to run.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8420";
      example = "0.0.0.0:8420";
      description = ''
        Address the hub's HTTP server binds. Defaults to localhost; expose it
        through a TLS-terminating reverse proxy rather than binding a public
        interface directly.
      '';
    };

    root = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/aos-hub";
      description = ''
        State directory holding the hub's sqlite database (hub.db) and any
        local_fs storage-binding roots. Provisioned as a systemd
        StateDirectory owned by the service account.
      '';
    };

    externalUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://hub.example.com";
      description = ''
        Externally reachable base URL, used verbatim in the setup snippets the
        hub renders (the `apr add` / `apm` / plain-Nix lines). Leave null to
        let the hub derive it from the listen address.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    aos.users.users.aos-hub = {
      uid = 802;
      group = "aos-hub";
      home = cfg.root;
      shell = "/sbin/nologin";
      description = "AOS registry hub";
      extraGroups = [];
    };
    aos.users.groups.aos-hub = {
      gid = 802;
      members = [];
    };

    systemd.services.aos-hub = {
      description = "AOS registry management hub (RFC-0004)";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      # Restart hardening. The hub exposes /healthz but does not yet emit
      # sd_notify READY=1/WATCHDOG=1, so a Type=notify readiness gate and
      # WatchdogSec are not wired up — that needs sd_notify support in the
      # binary (the `sd-notify` crate would do it). Until then we keep
      # Type=simple and harden the restart policy: always restart, back off,
      # and cap the restart rate so a crash loop surfaces as a failed unit
      # rather than spinning forever.
      #
      # TODO(rfc-0004): add sd_notify to `serve` (emit READY=1 after the
      # listener binds, WATCHDOG=1 periodically) and switch to Type=notify +
      # WatchdogSec for true readiness/liveness supervision.
      unitConfig = {
        # Cap the restart rate: more than 5 starts in 60s fails the unit
        # (so a crash loop surfaces as `failed`, not an endless respawn).
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart =
          "${cfg.package}/bin/aos-hub"
          + " --root ${lib.escapeShellArg cfg.root}"
          + " serve --listen ${lib.escapeShellArg cfg.listen}"
          + externalArg;
        Restart = "always";
        RestartSec = "5s";
        User = "aos-hub";
        Group = "aos-hub";
        # The hub opens $root/hub.db at startup and writes its sqlite WAL there;
        # StateDirectory provisions /var/lib/aos-hub (0750) owned by
        # the service account. When `root` is the default this is exactly that
        # path; an operator pointing `root` elsewhere must provision it.
        StateDirectory = "aos-hub";
        StateDirectoryMode = "0750";
        # Sandboxing: matches the registry-server role's profile. The hub needs
        # no privilege beyond reading its package and writing its StateDirectory.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
      };
    };
  };
}
