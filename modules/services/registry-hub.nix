##! modules/services/registry-hub.nix — the AOS registry hub (RFC-0004)
##!
##! Runs `aos-hub serve` as a hardened systemd service so operators
##! deploy the multi-tenant registry management WebUI *with* AOS, per RFC-0004's
##! operations section. The hub is local-first and self-contained: a single
##! binary plus a local database or a hybrid PostgreSQL backend, listening on
##! `--listen`. It
##! can terminate TLS in-process so authenticated listener evidence reaches the
##! typed route dispatcher without trusting forwarding headers.
##!
##! This contributes:
##!   * aos.users.users.aos-hub + group (a dedicated service account)
##!   * systemd.services.aos-hub running `aos-hub serve`
##!     under StateDirectory=aos-hub, with strict sandboxing
##!
##! Enable with `aos.registry-hub.enable = true`. The defaults bind localhost;
##! production deployments provide the native TLS credentials, bind their
##! public listener, and set `externalUrl` to the matching HTTPS origin.
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
    tlsCertificate = {
      handle = "tls-certificate";
      environment = "HUB_TLS_CERTIFICATE_FILE";
    };
    tlsPrivateKey = {
      handle = "tls-private-key";
      environment = "HUB_TLS_PRIVATE_KEY_FILE";
    };
    databaseUrl = {
      handle = "database-url";
      environment = "HUB_DATABASE_URL_FILE";
    };
    hybridIngressKey = {
      handle = "hybrid-ingress-key";
      environment = "HUB_HYBRID_INGRESS_KEY_FILE";
    };
    storageWorkKey = {
      handle = "storage-work-key";
      environment = "HUB_STORAGE_WORK_KEY_FILE";
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
  releaseEvidenceConfigured =
    cfg.deploymentId != null
    || builtins.any (value: value != null) (builtins.tail releaseEvidenceFields);
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
        Address the Hub listener binds. Defaults to localhost. Production
        deployments enable native TLS before binding a public interface.
      '';
    };

    root = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/aos-hub";
      description = ''
        State directory for the native Hub. Local mode holds its SQLite database
        (hub.db) and local_fs storage roots here. Hybrid mode keeps authoritative
        state in PostgreSQL and still uses this directory for local runtime state.
        The directory is provisioned as a systemd StateDirectory owned by the
        service account.
      '';
    };

    hybrid = {
      enable = lib.mkEnableOption "Worker-fronted Native Hub serving";

      workerUrl = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "https://[^[:space:]]+");
        default = null;
        example = "https://storage.example.com";
        description = "HTTPS origin of the paired storage Worker.";
      };

      originUrl = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "https://[^[:space:]]+");
        default = null;
        example = "https://hub-origin.example.com";
        description = "Private HTTPS origin the Worker uses to reach this Native Hub, including its TLS hostname.";
      };
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
        assertion =
          !cfg.hybrid.enable
          || (cfg.deploymentId != null
            && cfg.hybrid.workerUrl != null
            && cfg.hybrid.originUrl != null
            && cfg.credentials.databaseUrl != null
            && cfg.credentials.hybridIngressKey != null
            && cfg.credentials.storageWorkKey != null
            && cfg.externalUrl != null
            && lib.hasPrefix "https://" cfg.externalUrl);
        message = "hybrid Hub requires deploymentId, HTTPS externalUrl, workerUrl and originUrl, plus databaseUrl, hybridIngressKey, and storageWorkKey credentials";
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
        message = "Hub release evidence requires deploymentId, both receipt key ids, both receipt key credentials, releasePublicationKeys, and qualificationKeys together";
      }
      {
        assertion =
          (cfg.credentials.tlsCertificate == null)
          == (cfg.credentials.tlsPrivateKey == null);
        message = "native Hub TLS certificate and private-key credentials must be configured together";
      }
      {
        assertion =
          cfg.credentials.tlsCertificate
          == null
          || (cfg.externalUrl != null && lib.hasPrefix "https://" cfg.externalUrl);
        message = "native Hub TLS requires an HTTPS externalUrl";
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
      # and cap the restart rate in Native-only mode. Hybrid may start before
      # its Worker; keep retrying so it recovers when the paired Worker starts.
      #
      # TODO(rfc-0004): add sd_notify to `serve` (emit READY=1 after the
      # listener binds, WATCHDOG=1 periodically) and switch to Type=notify +
      # WatchdogSec for true readiness/liveness supervision.
      unitConfig = {
        StartLimitIntervalSec = if cfg.hybrid.enable then 0 else 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        ExecStart =
          "${cfg.package}/bin/aos-hub"
          + " --root ${lib.escapeShellArg cfg.root}"
          + " serve --listen ${lib.escapeShellArg cfg.listen}"
          + lib.optionalString cfg.hybrid.enable " --topology hybrid"
          + " --reindex-interval ${toString cfg.reindexInterval}"
          + externalArg;
        LoadCredential = loadCredentials;
        Environment =
          credentialEnvironment
          ++ ["HUB_DNS_JSON_ENDPOINT=${cfg.dnsJsonEndpoint}"]
          ++ lib.optionals cfg.hybrid.enable [
            "HUB_DEPLOYMENT_ID=${toString cfg.deploymentId}"
            "HUB_HYBRID_WORKER_URL=${toString cfg.hybrid.workerUrl}"
            "HUB_HYBRID_ORIGIN_URL=${toString cfg.hybrid.originUrl}"
          ]
          ++ lib.optionals (releaseEvidenceComplete && !cfg.hybrid.enable) [
            "HUB_DEPLOYMENT_ID=${cfg.deploymentId}"
          ]
          ++ lib.optionals releaseEvidenceComplete [
            "HUB_RELEASE_RECEIPT_KEY_ID=${cfg.releaseReceiptKeyId}"
            "HUB_CHANNEL_RECEIPT_KEY_ID=${cfg.channelReceiptKeyId}"
          ]
          ++ lib.optional (cfg.routePublicationPublicKey != null)
          "HUB_ROUTE_PUBLICATION_PUBLIC_KEY=${cfg.routePublicationPublicKey}";
        Restart = "always";
        RestartSec = if cfg.hybrid.enable then "15s" else "5s";
        User = "aos-hub";
        Group = "aos-hub";
        # Local mode opens $root/hub.db and writes its SQLite WAL here.
        # Hybrid mode uses PostgreSQL but retains a private runtime directory.
        # A nondefault root must be provisioned by the operator.
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
        AmbientCapabilities = lib.optional (cfg.credentials.tlsCertificate != null) "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = lib.optional (cfg.credentials.tlsCertificate != null) "CAP_NET_BIND_SERVICE";
      };
    };
  };
}
