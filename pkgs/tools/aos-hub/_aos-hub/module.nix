##! Package-owned AOS registry hub service declaration.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.registry-hub;
  serviceEnabled = config.aos.services.hub.enable;
  types = lib.types;
  operations = config.aos.abilities;
  resultOf = key: field:
    if key == "service-group"
    then operations.identity.operations.group.effects.hub.outputs.${field}
    else if key == "service-principal"
    then operations.identity.operations.principal.effects.hub.outputs.${field}
    else if key == "state-storage"
    then operations.filesystem.operations.persistentAllocate.effects.hub-state.outputs.${field}
    else if key == "network-readiness"
    then operations.network.operations.ready.effects.hub.outputs.${field}
    else throw "Unknown native Hub prerequisite '${key}'";
  principalName = "aos-hub";
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
  };
  credentialNames = builtins.attrNames credentialFields;
  configuredCredentialNames = builtins.filter (name: cfg.credentials.${name} != null) credentialNames;
  releaseEvidenceValues = [
    cfg.deploymentId
    cfg.releaseReceiptKeyId
    cfg.channelReceiptKeyId
    cfg.credentials.releaseReceiptKey
    cfg.credentials.channelReceiptKey
    cfg.credentials.releasePublicationKeys
    cfg.credentials.qualificationKeys
  ];
  releaseEvidenceConfigured = builtins.any (value: value != null) releaseEvidenceValues;
  releaseEvidenceComplete = builtins.all (value: value != null) releaseEvidenceValues;
  usesTls = cfg.credentials.tlsCertificate != null;
  boundedString = types.str;
  endpoint = types.strMatching "https://[!-~]+";
  optionalString = types.nullOr types.str;
  optionalCredential = types.nullOr (types.strMatching "[A-Za-z0-9][A-Za-z0-9._-]*");
  command = arguments: {
    executable = {
      path = "${package}/bin/aos-hub";
      inherit arguments;
    };
    ignore_failure = false;
  };
  credentialViews =
    builtins.map (name: {
      name = credentialFields.${name}.handle;
      reference = operations.credential.operations.deliver.effects."hub-${name}".outputs.path;
      encrypted = false;
      optional = false;
      environment_variable = credentialFields.${name}.environment;
    })
    configuredCredentialNames;
  environmentVariables =
    {
      HUB_DNS_JSON_ENDPOINT = cfg.dnsJsonEndpoint;
    }
    // lib.optionalAttrs releaseEvidenceComplete {
      HUB_DEPLOYMENT_ID = cfg.deploymentId;
      HUB_RELEASE_RECEIPT_KEY_ID = cfg.releaseReceiptKeyId;
      HUB_CHANNEL_RECEIPT_KEY_ID = cfg.channelReceiptKeyId;
    }
    // lib.optionalAttrs (cfg.routePublicationPublicKey != null) {
      HUB_ROUTE_PUBLICATION_PUBLIC_KEY = cfg.routePublicationPublicKey;
    };
  serviceFor = {
    views,
    tls,
  }: {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = lib.optionals tls ["bind-privileged-network-port"];
      privilege_bounds = {
        kind = "restricted";
        privileges = lib.optionals tls ["bind-privileged-network-port"];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "shared";
      host_clock_mutation = true;
      host_name_mutation = true;
      operating_system_log_access = true;
      operating_system_extension_access = true;
      operating_system_tunable_access = false;
      lock_execution_personality = false;
      writable_executable_memory = true;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = true;
      permit_elevated_file_identity = true;
      process_visibility = "all";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      operation_profile = "privileged";
      isolated_identity_mapping = "none";
    };
    service = "aos-hub";
    lifecycle = {
      description = "AOS registry management hub (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        (command (
          [
            "--root"
            cfg.root
            "serve"
            "--listen"
            cfg.listen
            "--reindex-interval"
            (toString cfg.reindexInterval)
          ]
          ++ lib.optionals (cfg.externalUrl != null) ["--external-url" cfg.externalUrl]
        ))
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "always";
      restart_delay_millis = 5000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    activationAfter = [
      (resultOf "network-readiness" "resource")
      (resultOf "state-storage" "resource")
    ];
    dependencies = {
      after = [
        (resultOf "network-readiness" "resource")
        (resultOf "state-storage" "resource")
      ];
      before = [];
      requires = [(resultOf "state-storage" "resource")];
      wants = [(resultOf "network-readiness" "resource")];
    };
    supervision = {
      startup_protocol = "process";
      notification_access = "none";
    };
    readiness = {
      mechanism = "process-running";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    start_policy = {
      accepted_exit_statuses = [];
      restart_preventing_exit_statuses = [];
      rate_interval_millis = 60000;
      rate_burst = 5;
    };
    credentials.views = views;
    storage.mounts = [
      {
        name = "state";
        source = resultOf "state-storage" "path";
        access = "read-write";
      }
    ];
    environment = {
      variables = environmentVariables;
      search_path = [];
    };
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = {
      principal = resultOf "service-principal" "name";
      primary_group = resultOf "service-group" "name";
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0022";
    };
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-system";
      home_access = "inaccessible";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = true;
    };
  };
  service = serviceFor {
    views = credentialViews;
    tls = usesTls;
  };
in {
  options.aos.registry-hub = {
    enable = lib.mkOption {
      type = types.bool;
      default = false;
      description = "Enable the AOS registry management hub.";
    };
    listen = lib.mkOption {
      type = boundedString;
      default = "127.0.0.1:8420";
      description = "Address and port on which the registry hub accepts requests.";
    };
    root = lib.mkOption {
      type = types.strMatching "/[ -~]*";
      default = "/var/lib/aos-hub";
      description = "Persistent directory containing the hub database and local storage bindings.";
    };
    externalUrl = lib.mkOption {
      type = optionalString;
      default = null;
      description = "Externally reachable base URL used in generated setup instructions.";
    };
    reindexInterval = lib.mkOption {
      type = types.ints.between 0 9007199254740991;
      default = 60;
      description = "Seconds between background re-index runs; zero disables them.";
    };
    dnsJsonEndpoint = lib.mkOption {
      type = endpoint;
      default = "https://dns.google/resolve";
      description = "HTTPS DNS-over-JSON endpoint used for domain verification.";
    };
    routePublicationPublicKey = lib.mkOption {
      type = optionalString;
      default = null;
      description = "Pinned non-secret key for the signed route-publication manifest.";
    };
    deploymentId = lib.mkOption {
      type = optionalString;
      default = null;
      description = "Immutable public deployment identity bound into release plans and receipts.";
    };
    releaseReceiptKeyId = lib.mkOption {
      type = optionalString;
      default = null;
      description = "Public key identity used to sign environment publication receipts.";
    };
    channelReceiptKeyId = lib.mkOption {
      type = optionalString;
      default = null;
      description = "Distinct public key identity used to sign channel receipts.";
    };
    credentials = lib.mapAttrs (_: _:
      lib.mkOption {
        type = optionalCredential;
        default = null;
        description = "Logical name of the system credential delivered to this hub role.";
      })
    credentialFields;
  };

  config = lib.mkMerge [
    {
      aos.services.hub = lib.mkDefault (service // {enable = cfg.enable;});

      assertions = [
        {
          assertion = !serviceEnabled || cfg.credentials.routeReservationKeys != null;
          message = "aos.registry-hub.credentials.routeReservationKeys is required";
        }
        {
          assertion = !serviceEnabled || cfg.credentials.domainProbeSignerManifest != null;
          message = "aos.registry-hub.credentials.domainProbeSignerManifest is required";
        }
        {
          assertion = !serviceEnabled || (cfg.credentials.routePublicationManifest == null) == (cfg.routePublicationPublicKey == null);
          message = "routePublicationManifest and routePublicationPublicKey must be configured together";
        }
        {
          assertion = !serviceEnabled || !releaseEvidenceConfigured || releaseEvidenceComplete;
          message = "native Hub release evidence requires deploymentId, both receipt key ids, both receipt key credentials, releasePublicationKeys, and qualificationKeys together";
        }
        {
          assertion = !serviceEnabled || (cfg.credentials.tlsCertificate == null) == (cfg.credentials.tlsPrivateKey == null);
          message = "native Hub TLS certificate and private-key credentials must be configured together";
        }
        {
          assertion = !serviceEnabled || cfg.credentials.tlsCertificate == null || (cfg.externalUrl != null && lib.hasPrefix "https://" cfg.externalUrl);
          message = "native Hub TLS requires an HTTPS externalUrl";
        }
        {
          assertion = !serviceEnabled || cfg.releaseReceiptKeyId == null || cfg.channelReceiptKeyId == null || cfg.releaseReceiptKeyId != cfg.channelReceiptKeyId;
          message = "releaseReceiptKeyId and channelReceiptKeyId must be distinct";
        }
      ];
    }
    (lib.mkIf serviceEnabled {
      aos.abilities = {
        identity.operations.group.effects.hub.input = {
          name = principalName;
          requested_id = 802;
        };
        identity.operations.principal.effects.hub.input = {
          name = principalName;
          requested_id = 802;
          description = "AOS registry hub";
          home_directory = cfg.root;
          login_access = "disabled";
          primary_group = resultOf "service-group" "name";
          supplementary_groups = [];
        };
        filesystem.operations.persistentAllocate.effects.hub-state.lifetime = "persistent";
        filesystem.operations.persistentAllocate.effects.hub-state.input = {
          path = cfg.root;
          mode = "0750";
          owner = resultOf "service-principal" "name";
          group = resultOf "service-group" "name";
        };
        network.operations.ready.effects.hub.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        credential.operations.deliver.effects = builtins.listToAttrs (builtins.map (name: {
            name = "hub-${name}";
            value.input = {
              name = cfg.credentials.${name};
              scope = "system";
              encrypted = false;
            };
          })
          configuredCredentialNames);
      };
    })
  ];
}
