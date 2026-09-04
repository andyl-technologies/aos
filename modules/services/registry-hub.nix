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
  credentialDirectory = "/run/credentials/aos-hub.service";
  credentialFields = {
    jwtSecret = {
      handle = "jwt-secret";
      environment = "HUB_JWT_SECRET_FILE";
    };
    deliveryAttestationKey = {
      handle = "delivery-attestation-key";
      environment = "HUB_DELIVERY_ATTESTATION_KEY_FILE";
    };
    domainProbeSignerManifest = {
      handle = "domain-probe-signers";
      environment = "HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE";
    };
    routePublicationManifest = {
      handle = "route-publication-manifest";
      environment = "HUB_ROUTE_PUBLICATION_MANIFEST_FILE";
    };
    routeReservationKeys = {
      handle = "route-reservation-keys";
      environment = "HUB_ROUTE_RESERVATION_KEYS_FILE";
    };
    secretVersionManifest = {
      handle = "secret-version-manifest";
      environment = "HUB_SECRET_VERSION_MANIFEST_FILE";
    };
    cloudflareApiToken = {
      handle = "cloudflare-api-token";
      environment = "HUB_CLOUDFLARE_API_TOKEN_FILE";
    };
    releaseReceiptKey = {
      handle = "release-receipt-key";
      environment = "HUB_RELEASE_RECEIPT_KEY_FILE";
    };
    channelReceiptKey = {
      handle = "channel-receipt-key";
      environment = "HUB_CHANNEL_RECEIPT_KEY_FILE";
    };
    releasePublicationKeys = {
      handle = "release-publication-keys";
      environment = "HUB_RELEASE_PUBLICATION_KEYS_FILE";
    };
    qualificationKeys = {
      handle = "qualification-keys";
      environment = "HUB_QUALIFICATION_KEYS_FILE";
    };
  };
  configuredCredentials = lib.filterAttrs (name: _: cfg.credentials.${name} != null) credentialFields;
  loadCredentials =
    lib.mapAttrsToList (
      name: spec: "${spec.handle}:/run/credentials/@system/${cfg.credentials.${name}}"
    )
    configuredCredentials;
  credentialEnvironment =
    lib.mapAttrsToList (
      _: spec: "${spec.environment}=${credentialDirectory}/${spec.handle}"
    )
    configuredCredentials;
  releaseEvidenceFields = [
    cfg.deploymentId
    cfg.releaseReceiptKeyId
    cfg.channelReceiptKeyId
    cfg.credentials.releaseReceiptKey
    cfg.credentials.channelReceiptKey
    cfg.credentials.releasePublicationKeys
    cfg.credentials.qualificationKeys
  ];
  releaseEvidenceConfigured = builtins.any (value: value != null) releaseEvidenceFields;
  releaseEvidenceComplete = builtins.all (value: value != null) releaseEvidenceFields;
in {
  options.aos.registry-hub = {
    enable = lib.mkEnableOption "the AOS registry management hub (aos-hub)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-hub;
      defaultText = "pkgs.aos-hub";
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
        local_fs storage-binding roots. The native Hub provisions its
        deployment-owned instance-default binding at the `storage` directory
        beneath this root. The root is provisioned as a systemd StateDirectory
        owned by the service account.
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

    reindexInterval = lib.mkOption {
      type = lib.serviceTypes.nonNegativeInt;
      default = 60;
      description = "Seconds between background re-index runs; zero disables them.";
    };

    dnsJsonEndpoint = lib.mkOption {
      type = lib.types.strMatching "https://[^[:space:]]+";
      default = "https://dns.google/resolve";
      description = "HTTPS DNS-over-JSON endpoint used for domain verification.";
    };

    routePublicationPublicKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Pinned non-secret Ed25519 key for the signed route-publication manifest.";
    };

    deploymentId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "aos-production-us-west-v1";
      description = ''
        Immutable public deployment identity bound into canonical release
        plans and receipts. Configuring it enables the release evidence
        authority and requires every role-separated key input below.
      '';
    };

    releaseReceiptKeyId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Public key identity used to sign environment publication receipts.";
    };

    channelReceiptKeyId = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Distinct public key identity used to sign channel receipts.";
    };

    credentials = lib.mapAttrs (_: _:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description = "Name of a platform credential beneath /run/credentials/@system.";
      })
    credentialFields;
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.credentials.routeReservationKeys != null;
        message = "aos.registry-hub.credentials.routeReservationKeys is required";
      }
      {
        assertion = cfg.credentials.domainProbeSignerManifest != null;
        message = "aos.registry-hub.credentials.domainProbeSignerManifest is required";
      }
      {
        assertion =
          (cfg.credentials.routePublicationManifest == null)
          == (cfg.routePublicationPublicKey == null);
        message = "routePublicationManifest and routePublicationPublicKey must be configured together";
      }
      {
        assertion = !releaseEvidenceConfigured || releaseEvidenceComplete;
        message = "native Hub release evidence requires deploymentId, both receipt key ids, both receipt key credentials, releasePublicationKeys, and qualificationKeys together";
      }
      {
        assertion =
          cfg.releaseReceiptKeyId
          == null
          || cfg.channelReceiptKeyId == null
          || cfg.releaseReceiptKeyId != cfg.channelReceiptKeyId;
        message = "releaseReceiptKeyId and channelReceiptKeyId must be distinct";
      }
    ];
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
          + " --reindex-interval ${toString cfg.reindexInterval}"
          + externalArg;
        LoadCredential = loadCredentials;
        Environment =
          credentialEnvironment
          ++ ["HUB_DNS_JSON_ENDPOINT=${cfg.dnsJsonEndpoint}"]
          ++ lib.optionals releaseEvidenceComplete [
            "HUB_DEPLOYMENT_ID=${cfg.deploymentId}"
            "HUB_RELEASE_RECEIPT_KEY_ID=${cfg.releaseReceiptKeyId}"
            "HUB_CHANNEL_RECEIPT_KEY_ID=${cfg.channelReceiptKeyId}"
          ]
          ++ lib.optional (cfg.routePublicationPublicKey != null)
          "HUB_ROUTE_PUBLICATION_PUBLIC_KEY=${cfg.routePublicationPublicKey}";
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
