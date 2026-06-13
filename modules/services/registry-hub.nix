##! modules/services/registry-hub.nix — the AOS registry hub (RFC-0004)
##!
##! Runs `aos-registry-hub serve` as a hardened systemd service so operators
##! deploy the multi-tenant registry management WebUI *with* AOS, per RFC-0004's
##! operations section. The hub is local-first and self-contained: a single
##! binary plus a sqlite database under `--root`, listening on `--listen`. It
##! shells out to nothing, so — unlike the registry *server* role — it needs no
##! PATH wiring.
##!
##! This contributes:
##!   * aos.users.users.aos-registry-hub + group (a dedicated service account)
##!   * systemd.services.aos-registry-hub running `aos-registry-hub serve`
##!     under StateDirectory=aos-registry-hub, with strict sandboxing
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
    enable = lib.mkEnableOption "the AOS registry management hub (aos-registry-hub)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-registry-hub;
      defaultText = lib.literalExpression "pkgs.aos-registry-hub";
      description = "The aos-registry-hub package to run.";
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
      default = "/var/lib/aos-registry-hub";
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
    aos.users.users.aos-registry-hub = {
      uid = 802;
      group = "aos-registry-hub";
      home = cfg.root;
      shell = "/sbin/nologin";
      description = "AOS registry hub";
      extraGroups = [];
    };
    aos.users.groups.aos-registry-hub = {
      gid = 802;
      members = [];
    };

    systemd.services.aos-registry-hub = {
      description = "AOS registry management hub (RFC-0004)";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      serviceConfig = {
        ExecStart =
          "${cfg.package}/bin/aos-registry-hub"
          + " --root ${lib.escapeShellArg cfg.root}"
          + " serve --listen ${lib.escapeShellArg cfg.listen}"
          + externalArg;
        Restart = "on-failure";
        RestartSec = "5s";
        User = "aos-registry-hub";
        Group = "aos-registry-hub";
        # The hub opens $root/hub.db at startup and writes its sqlite WAL there;
        # StateDirectory provisions /var/lib/aos-registry-hub (0750) owned by
        # the service account. When `root` is the default this is exactly that
        # path; an operator pointing `root` elsewhere must provision it.
        StateDirectory = "aos-registry-hub";
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
