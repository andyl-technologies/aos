##! modules/sandbox/controller-service.nix — production unprivileged controller
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.controllerService;
  controller = config.aos.sandbox.controller;
  brokers = config.aos.sandbox;
  ownershipAuthority =
    brokers.ownershipAuthority or {
      enable = false;
      credentials.sessionKey = null;
    };
  policyAuthority = brokers.policyAuthority or {enable = false;};
  normalRootProfile =
    if policyAuthority.enable
    then policyAuthority._normalStartupProfile
    else null;
  cacheSignerView = brokers.cacheSignerView or {enable = false;};
  sourceSignerView = brokers.sourceSignerView or {enable = false;};
  brokerSession = import ./_broker-session-credentials.nix {inherit lib pkgs;};
  brokerSessionEndpoints = map (endpoint:
    endpoint
    // {
      role = "client";
      required = !(endpoint.optionalManifest or false);
      description = "controller-to-${endpoint.name}";
      options = {
        manifest = "brokerSession${endpoint.optionName}Manifest";
        hello = "brokerSession${endpoint.keyOptionName or endpoint.optionName}HelloKey";
        record = "brokerSession${endpoint.keyOptionName or endpoint.optionName}RecordKey";
      };
    }) [
    {
      name = "host";
      optionName = "Host";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/host";
    }
    {
      name = "storage";
      optionName = "Storage";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/storage";
    }
    {
      name = "mount";
      optionName = "Mount";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/mount";
    }
    {
      name = "network";
      optionName = "Network";
      journalRoot = "/var/lib/aos/sandboxd/broker-session/network";
    }
    {
      name = "mount-fuse";
      optionName = "MountFuse";
      keyOptionName = "Mount";
      optionalManifest = true;
      journalRoot = "/var/lib/aos/sandboxd/broker-session/mount-fuse";
    }
  ];
  brokerSessionConfiguration = brokerSession.configure cfg.credentials brokerSessionEndpoints;
  method46Floor = import ./_method46-tpm-floor.nix {inherit lib;};
  method46FloorConfiguration = method46Floor.configure cfg.method46TpmFloor;
  nodeCredentials =
    lib.optional (cfg.credentials.nodeId != null)
    "node-id:/run/credentials/@system/${cfg.credentials.nodeId}";
  cacheReplayCredentials =
    lib.optional (cfg.credentials.cacheReplayBundle != null)
    "cache-replay-bundle:/run/credentials/@system/${cfg.credentials.cacheReplayBundle}";
  cacheReadbackCredentials = lib.optionals (cfg.credentials.cacheOwnerReadbackSigningKey != null && cfg.credentials.cacheOwnerReadbackPublicKey != null) [
    "cache-owner-readback-signing-key:/run/credentials/@system/${cfg.credentials.cacheOwnerReadbackSigningKey}"
    "cache-owner-readback-public-key:/run/credentials/@system/${cfg.credentials.cacheOwnerReadbackPublicKey}"
  ];
  controllerHoldCredentials = lib.optionals (cfg.credentials.controllerHoldSigningKey != null && cfg.credentials.controllerHoldPublicKey != null) [
    "controller-hold-signing-key:/run/credentials/@system/${cfg.credentials.controllerHoldSigningKey}"
    "controller-hold-public-key:/run/credentials/@system/${cfg.credentials.controllerHoldPublicKey}"
  ];
  guestRootTemplateCredentials = [
    "guest-root-package-binding-v1:${pkgs.aos-sandbox-guest-root-template}/package-binding"
    "guest-root-tree-digest-v1:${pkgs.aos-sandbox-guest-root-template}/root-tree-digest"
  ];
  brokerPlanCredentials = lib.optionals (cfg.credentials.brokerPlanSigningKey != null) (
    ["broker-plan-signing-key:/run/credentials/@system/${cfg.credentials.brokerPlanSigningKey}"]
    ++ lib.optional (brokers.hostBroker.credentials.brokerPlanPolicy != null)
    "broker-plan-policy.cbor:/run/credentials/@system/${brokers.hostBroker.credentials.brokerPlanPolicy}"
    ++ lib.optional (brokers.hostBroker.credentials.brokerPlanPublicKey != null)
    "broker-plan-public-key:/run/credentials/@system/${brokers.hostBroker.credentials.brokerPlanPublicKey}"
    ++ lib.optional (brokers.hostBroker.credentials.brokerRevocationScope != null)
    "broker-revocation-scope:/run/credentials/@system/${brokers.hostBroker.credentials.brokerRevocationScope}"
  );
  mountPlanCredentials = lib.optionals (cfg.credentials.brokerPlanSigningKey != null) (
    lib.optional (brokers.mountBroker.credentials.brokerPlanPolicy != null)
    "mount-broker-plan-policy.cbor:/run/credentials/@system/${brokers.mountBroker.credentials.brokerPlanPolicy}"
    ++ lib.optional (brokers.mountBroker.credentials.brokerPlanPublicKey != null)
    "mount-broker-plan-public-key:/run/credentials/@system/${brokers.mountBroker.credentials.brokerPlanPublicKey}"
    ++ lib.optional (brokers.mountBroker.credentials.brokerRevocationScope != null)
    "mount-broker-revocation-scope:/run/credentials/@system/${brokers.mountBroker.credentials.brokerRevocationScope}"
  );
  attachTrustCredential = brokers.hostBroker.credentials.opensshAttachTrust or null;
  attachGrantPublicKeyCredential = brokers.hostBroker.credentials.opensshAttachGrantPublicKey or null;
  opensshAttachCredentials = lib.optionals (cfg.credentials.opensshAttachGrantSigningKey != null) (
    ["openssh-attach-grant-signing-key:/run/credentials/@system/${cfg.credentials.opensshAttachGrantSigningKey}"]
    ++ lib.optional (cfg.credentials.opensshAttachCaSigningKey != null)
    "openssh-attach-ca-signing-key:/run/credentials/@system/${cfg.credentials.opensshAttachCaSigningKey}"
    ++ lib.optional (attachTrustCredential != null)
    "openssh-attach-trust.json:/run/credentials/@system/${attachTrustCredential}"
    ++ lib.optional (attachGrantPublicKeyCredential != null)
    "openssh-attach-grant-public-key:/run/credentials/@system/${attachGrantPublicKeyCredential}"
  );
  ownershipCredentials = lib.optionals ownershipAuthority.enable (
    lib.optional (ownershipAuthority.credentials.sessionKey != null)
    "ownership-session-key:/run/credentials/@system/${ownershipAuthority.credentials.sessionKey}"
    ++ lib.optional (brokers.hostBroker.credentials.ownershipLeasePolicy != null)
    "ownership-lease-policy.cbor:/run/credentials/@system/${brokers.hostBroker.credentials.ownershipLeasePolicy}"
    ++ lib.optional (brokers.hostBroker.credentials.ownershipLeasePublicKey != null)
    "ownership-lease-public-key:/run/credentials/@system/${brokers.hostBroker.credentials.ownershipLeasePublicKey}"
  );
  publicCredentialNames = {
    publicApiServerCert = "public-api-server-cert";
    publicApiServerKey = "public-api-server-key";
    publicApiClientCa = "public-api-client-ca";
    publicApiPrincipals = "public-api-principals";
  };
  publicCredentials = lib.optionals cfg.publicApi.enable (
    lib.mapAttrsToList (option: name: "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
    (lib.filterAttrs (option: _: cfg.credentials.${option} != null) publicCredentialNames)
  );
  bootstrapCredentials = lib.optionals (cfg.publicApi.enable && cfg.credentials.publicApiEntitlements != null) [
    "public-api-entitlements:/run/credentials/@system/${cfg.credentials.publicApiEntitlements}"
    "public-api-entitlement-public-key:/run/credentials/@system/${cfg.credentials.publicApiEntitlementPublicKey}"
  ];
  operatorRecoveryCredentials = lib.optionals (cfg.credentials.operatorRecoveryControllerKey != null) [
    "operator-recovery-controller-key-v1:/run/credentials/@system/${cfg.credentials.operatorRecoveryControllerKey}"
    "operator-recovery-storage-owner-key-v1:/run/credentials/@system/${cfg.credentials.operatorRecoveryStorageOwnerPublicKey}"
  ];
  publisherScopeCredential =
    lib.optional cfg.publisherIngress.enable
    "publisher-service-scope-v1:/run/credentials/@system/${cfg.credentials.publisherServiceScope}";
  publisherPolicySourceCredentials = lib.optionals cfg.publisherIngress.enable [
    "publisher-policy-source-v1:/run/credentials/@system/${cfg.credentials.publisherPolicySource}"
    "publisher-policy-v1.cbor:/run/credentials/@system/${cfg.credentials.publisherPolicy}"
    "publisher-policy-source-public-key-v1:/run/credentials/@system/${cfg.credentials.publisherPolicySourcePublicKey}"
  ];
  gitUploadBootstrapCredentials = lib.optionals cfg.gitUploadBootstrap.enable [
    "git-upload-capacity-v1.cbor:/run/credentials/@system/git-upload-capacity-v1.cbor"
  ];
  projectAuthorizationIssuerCredential =
    lib.optional (cfg.credentials.projectAuthorizationIssuer != null)
    "project-authorization-issuer-v2:/run/credentials/@system/${cfg.credentials.projectAuthorizationIssuer}";
  controllerSourceTreeSeedIssuerCredential =
    lib.optional (cfg.credentials.controllerSourceTreeSeedIssuer != null)
    "controller-source-tree-seed-issuer-v1:/run/credentials/@system/${cfg.credentials.controllerSourceTreeSeedIssuer}";
  sourceGenesisPacketCredentials = lib.optionals (cfg.credentials.controllerSourceTreeSeed != null && cfg.credentials.projectAuthorizationSource != null) [
    "controller-source-tree-seed-v1:/run/credentials/@system/${cfg.credentials.controllerSourceTreeSeed}"
    "project-authorization-source-v2:/run/credentials/@system/${cfg.credentials.projectAuthorizationSource}"
  ];
  sourceSuccessorCredentials = lib.optionals cfg.sourceSuccessorIssuance.enable [
    "controller-source-successor-admin-seed-v2:/run/credentials/@system/controller-source-successor-admin-seed-v2"
    "controller-source-successor-intent-v2:/run/credentials/@system/controller-source-successor-intent-v2"
  ];
in {
  options.aos.sandbox.controllerService = {
    enable = lib.mkEnableOption "the production unprivileged sandbox node controller";

    publicApi.enable = lib.mkEnableOption "the registered mutual-TLS controller API on /run/aos/sandboxd/public.sock";

    sourceSuccessorIssuance.enable = lib.mkEnableOption "the exclusive one-shot first Source successor issuer; never the Source mutation consumer";

    publisherIngress.enable = lib.mkEnableOption "the exact-process project publisher registration channel; publication effects remain unavailable";

    gitUploadBootstrap.enable = lib.mkEnableOption "the non-admitting Git capacity bootstrap under an independently designated full-project admin policy issuer; no upload/export activation";

    gitReadInspection.enable = lib.mkEnableOption "the fixed Gateway read-scope inspection channel, without Git admission or backend effects";

    publisherIngress.uid = lib.mkOption {
      type = lib.types.int;
      default = 991;
      description = "Dedicated networkless publisher service UID, matched to the protected scope credential.";
    };

    publisherIngress.gid = lib.mkOption {
      type = lib.types.int;
      default = 991;
      description = "Dedicated networkless publisher service GID, matched to the protected scope credential.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The independently packaged unprivileged controller executable.";
    };

    method46TpmFloor = method46Floor.options;

    credentials =
      {
        nodeId = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External system credential containing the raw nonzero 16-byte node identity.";
        };
        brokerPlanSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external 32-byte controller broker-plan signing seed for authority publications and Guardian arm plans.";
        };
        opensshAttachGrantSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external 32-byte seed for the dedicated signed public OpenSSH attach pending grant.";
        };
        opensshAttachCaSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional external Ed25519 OpenSSH user CA private key for authorized attachment certificate issuance.";
        };
        cacheReplayBundle = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional protected canonical cache Replay bundle; required for clean cache bootstrap unless the controller source journal was provisioned earlier.";
        };
        cacheOwnerReadbackSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional Controller-held v1 diagnostic Cache readback seed; it is not the separate Cache-only AOSCRB02 signer key and no Create publication consumes it.";
        };
        cacheOwnerReadbackPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional matching 80-byte AOSCPK01 pin for the Controller-held v1 diagnostic seed.";
        };
        controllerHoldSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional separate-purpose 32-byte Controller hold readback signing seed; no Q04 exchange consumes it.";
        };
        controllerHoldPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional matching 80-byte AOSCTK01 Controller hold signer pin for local seed verification.";
        };
        publisherServiceScope = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External 64-byte AOSPMS01 scope: principal, project, cache resource, publisher UID/GID; never derived from socket credentials.";
        };
        publisherPolicySource = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External 272-byte signed AOSPSC01 initial publisher-policy source, bound to the publisher principal, node, project, and cache resource.";
        };
        publisherPolicy = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Exact canonical publisher policy CBOR committed by the signed AOSPSC01 source.";
        };
        publisherPolicySourcePublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated 32-byte Ed25519 verifier for the publisher-policy source.";
        };
        projectAuthorizationIssuer = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional separately provisioned 80-byte AOSPAK02 project-authorization issuer pin; absence keeps protected project-authorization retention closed.";
        };
        controllerSourceTreeSeedIssuer = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional separately provisioned 80-byte AOSCSK01 Controller Source-tree seed public verifier; absence keeps fixed-issuer seed verification closed.";
        };
        controllerSourceTreeSeed = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional externally signed 224-byte AOSCSE01 startup input; delivery does not admit Source genesis or open Create.";
        };
        projectAuthorizationSource = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional independently signed 224-byte AOSPSC02 paired with the Source seed; legacy AOSPSC01 publisher policy is not accepted.";
        };
        publicApiEntitlements = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Optional signed canonical principal-specific first-capability entitlements; bootstrap stays closed when absent.";
        };
        publicApiEntitlementPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated externally provisioned Ed25519 verifier for first-capability entitlements.";
        };
        operatorRecoveryControllerKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Dedicated AOSORCK1 Ed25519 controller Repair signing record; null keeps public Repair closed.";
        };
        operatorRecoveryStorageOwnerPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "Independently provisioned AOSORSK1 Storage owner public-key record for Repair receipts.";
        };
      }
      // brokerSession.mkOptions brokerSessionEndpoints
      // lib.mapAttrs (_: name:
        lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External protected credential loaded as ${name} for the public TLS endpoint.";
        })
      publicCredentialNames;
  };

  config = lib.mkIf cfg.enable {
    environment.etc."aos/method46-tpm-floor/controller-mode".text = method46FloorConfiguration.modeText;

    assertions =
      [
        {
          assertion = !cfg.gitReadInspection.enable
            || (cfg.publicApi.enable && cfg.publisherIngress.enable && cfg.gitUploadBootstrap.enable
              && config.aos.sandbox.gitGatewayTransport.enable
              && !cfg.sourceSuccessorIssuance.enable
              && cfg.credentials.publicApiClientCa == config.aos.sandbox.gitGatewayTransport.credentials.clientCa
              && cfg.credentials.publicApiPrincipals == config.aos.sandbox.gitGatewayTransport.credentials.principals
              && controller.uid != config.aos.sandbox.gitGatewayTransport.uid
              && controller.gid != config.aos.sandbox.gitGatewayTransport.gid);
          message = "Git inspection requires the same independently supplied CA/registration map, distinct fixed owners, original publisher/Cache bootstrap and the registered Controller API; it activates no Git effects.";
        }
        {
          assertion = cfg.credentials.nodeId != null;
          message = "aos.sandbox.controllerService.credentials.nodeId is required";
        }
        {
          assertion =
            !cfg.sourceSuccessorIssuance.enable
            || (!cfg.publicApi.enable && !cfg.publisherIngress.enable
              && normalRootProfile != null && cfg.package == pkgs.aos-sandboxd);
          message = "Source successor issuance requires the exact selected Controller/normal-Root image and exclusive nonpublic issue mode";
        }
        {
          assertion =
            !cfg.sourceSuccessorIssuance.enable
            || (cfg.credentials.controllerHoldSigningKey != null
              && cfg.credentials.controllerHoldPublicKey != null
              && cfg.credentials.controllerSourceTreeSeedIssuer != null
              && cfg.credentials.projectAuthorizationIssuer != null);
          message = "Source successor issuance requires separately provisioned Controller readback and independent administrative public role pins";
        }
        {
          assertion =
            (cfg.credentials.cacheOwnerReadbackSigningKey == null)
            == (cfg.credentials.cacheOwnerReadbackPublicKey == null);
          message = "Cache owner readback signing seed and role-specific public pin must be provisioned together";
        }
        {
          assertion =
            cfg.credentials.cacheOwnerReadbackSigningKey
            == null
            || (config.aos.sandbox.policyAuthority.enable
              && config.aos.sandbox.policyAuthority.credentials.cacheOwnerReadbackPublicKey
              == cfg.credentials.cacheOwnerReadbackPublicKey);
          message = "Cache owner readback requires the policy authority to load the same fixed public pin credential";
        }
        {
          assertion =
            (cfg.credentials.controllerHoldSigningKey == null)
            == (cfg.credentials.controllerHoldPublicKey == null);
          message = "Controller hold readback signing seed and role-specific public pin must be provisioned together";
        }
        {
          assertion =
            cfg.credentials.controllerHoldSigningKey
            == null
            || (config.aos.sandbox.policyAuthority.enable
              && config.aos.sandbox.policyAuthority.credentials.controllerHoldPublicKey
              == cfg.credentials.controllerHoldPublicKey);
          message = "Controller hold readback requires the policy authority to load the same fixed public pin credential";
        }
        {
          assertion = (cfg.credentials.operatorRecoveryControllerKey == null) == (cfg.credentials.operatorRecoveryStorageOwnerPublicKey == null);
          message = "controller operator Recovery signing and Storage owner trust credentials must be provisioned together";
        }
        {
          assertion = (cfg.credentials.controllerSourceTreeSeed == null) == (cfg.credentials.projectAuthorizationSource == null);
          message = "Source genesis startup seed and independent project authorization packets must be provisioned together";
        }
        {
          assertion = cfg.credentials.controllerSourceTreeSeed == null || (cfg.credentials.controllerSourceTreeSeedIssuer != null && cfg.credentials.projectAuthorizationIssuer != null);
          message = "Source genesis packet delivery requires both existing independently provisioned issuer pins";
        }
        {
          assertion = !cfg.publisherIngress.enable || cfg.credentials.publisherServiceScope != null;
          message = "publisher ingress requires an externally provisioned publisherServiceScope credential";
        }
        {
          assertion =
            !cfg.gitUploadBootstrap.enable
            || (cfg.publisherIngress.enable
              && !cfg.sourceSuccessorIssuance.enable
              && cfg.credentials.publisherPolicy == "publisher-policy-v1.cbor");
          message = "Git bootstrap requires publisher ingress and the exact protected plaintext @system policy mapping; external admin designation/signing/capacity provisioning remain required.";
        }
        {
          assertion =
            !cfg.publisherIngress.enable
            || (cfg.credentials.publisherPolicySource
              != null
              && cfg.credentials.publisherPolicy != null
              && cfg.credentials.publisherPolicySourcePublicKey != null);
          message = "publisher ingress requires signed publisher policy source, canonical policy, and dedicated verification key credentials";
        }
        {
          assertion = !cfg.publisherIngress.enable || (cfg.publisherIngress.uid > 0 && cfg.publisherIngress.uid < 65536 && cfg.publisherIngress.gid > 0 && cfg.publisherIngress.gid < 65536);
          message = "publisher ingress UID and GID must be within 1..65535";
        }
        {
          assertion = !cfg.publisherIngress.enable || (cfg.publisherIngress.uid != controller.uid && cfg.publisherIngress.gid != controller.gid);
          message = "publisher execution must not share the controller UID or GID";
        }
        {
          assertion = brokers.hostBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.hostBroker";
        }
        {
          assertion =
            cfg.credentials.brokerPlanSigningKey
            == null
            || (
              brokers.hostBroker.credentials.brokerPlanPolicy
              != null
              && brokers.hostBroker.credentials.brokerPlanPublicKey != null
              && brokers.hostBroker.credentials.brokerRevocationScope != null
            );
          message = "aos.sandbox.controllerService broker-plan signing requires the Host broker's public plan policy, key, and revocation scope";
        }
        {
          assertion =
            (cfg.credentials.opensshAttachGrantSigningKey
              == null
              && cfg.credentials.opensshAttachCaSigningKey == null
              && attachTrustCredential == null
              && attachGrantPublicKeyCredential == null)
            || (cfg.credentials.opensshAttachGrantSigningKey
              != null
              && cfg.credentials.opensshAttachCaSigningKey != null
              && attachTrustCredential != null
              && attachGrantPublicKeyCredential != null);
          message = "aos.sandbox.controllerService OpenSSH attach grants require the dedicated signing key and both Host attach trust credentials together";
        }
        {
          assertion =
            cfg.credentials.brokerPlanSigningKey
            == null
            || (
              brokers.mountBroker.credentials.brokerPlanPolicy
              != null
              && brokers.mountBroker.credentials.brokerPlanPublicKey != null
              && brokers.mountBroker.credentials.brokerRevocationScope != null
            );
          message = "aos.sandbox.controllerService broker-plan signing requires the Mount broker's independent public plan policy, key, and revocation scope";
        }
        {
          assertion = brokers.storageBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.storageBroker";
        }
        {
          assertion = brokers.mountBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.mountBroker";
        }
        {
          assertion = brokers.networkBroker.enable;
          message = "aos.sandbox.controllerService requires aos.sandbox.networkBroker";
        }
        {
          assertion = !ownershipAuthority.enable || ownershipAuthority.credentials.sessionKey != null;
          message = "aos.sandbox.controllerService ownership resumption requires the ownership session key";
        }
        {
          assertion =
            !ownershipAuthority.enable
            || (
              brokers.hostBroker.credentials.ownershipLeasePolicy
              != null
              && brokers.hostBroker.credentials.ownershipLeasePublicKey != null
            );
          message = "aos.sandbox.controllerService ownership resumption requires the Host broker's lease policy and public key";
        }
      ]
      ++ brokerSessionConfiguration.assertions
      ++ method46FloorConfiguration.assertions
      ++ [
        {
          assertion = !cfg.method46TpmFloor.required || (config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0" && config.aos.security.selinux.mode == "enforcing" && cfg.package == pkgs.aos-sandboxd);
          message = "required Controller TPM floor requires immutable enforcing SELinux and the exact AOS package; owner IDs are independently compiled from the immutable module assignment";
        }
        {
          assertion =
            !(cfg.method46TpmFloor.required && brokers.storageBroker.method46TpmFloor.required)
            || (cfg.method46TpmFloor.indexAuthCredential
              != brokers.storageBroker.method46TpmFloor.indexAuthCredential
              && cfg.method46TpmFloor.provisionCredential != brokers.storageBroker.method46TpmFloor.provisionCredential);
          message = "Controller and Storage TPM floors require separate owner-specific public and NV-auth credential sources";
        }
      ]
      ++ lib.mapAttrsToList (option: _: {
        assertion = !cfg.publicApi.enable || cfg.credentials.${option} != null;
        message = "aos.sandbox.controllerService.credentials.${option} is required when publicApi.enable is true";
      })
      publicCredentialNames
      ++ [
        {
          assertion =
            (cfg.credentials.publicApiEntitlements == null)
            == (cfg.credentials.publicApiEntitlementPublicKey == null);
          message = "public API first-capability entitlements and their verifier must be provisioned together";
        }
      ];

    aos.users.users.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      uid = cfg.publisherIngress.uid;
      group = "aos-view-publisher";
      home = "/";
      shell = "/sbin/nologin";
      description = "AOS networkless project publisher registration process";
      extraGroups = [];
    };
    aos.users.groups.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      gid = cfg.publisherIngress.gid;
      members = [];
    };

    systemd.sockets.aos-sandboxd-publisher = lib.mkIf cfg.publisherIngress.enable {
      description = "AOS project publisher registration listener";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/sandbox-publisher/control.sock";
        FileDescriptorName = "aos-sandboxd-publisher";
        Service = "aos-sandboxd.service";
        Accept = false;
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "aos-sandboxd";
        SocketGroup = "aos-view-publisher";
        SocketMode = "0660";
        DirectoryMode = "0711";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-sandboxd = {
      description = "AOS unprivileged sandbox node controller";
      wantedBy = ["multi-user.target"];
      requires =
        [
          "aos-sandbox-hostd.service"
          "aos-storaged.service"
          "aos-sandbox-mountd.service"
          "aos-netd.service"
        ]
        ++ lib.optional policyAuthority.enable "aos-sandbox-policy-authorityd.service"
        ++ lib.optional policyAuthority.enable "aos-sandbox-cache-journal-view.service"
        ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
        ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service"
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket"
        ++ lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
      after =
        [
          "aos-sandbox-hostd.service"
          "aos-storaged.service"
          "aos-sandbox-mountd.service"
          "aos-netd.service"
          "local-fs.target"
        ]
        ++ lib.optional policyAuthority.enable "aos-sandbox-policy-authorityd.service"
        ++ lib.optional policyAuthority.enable "aos-sandbox-cache-journal-view.service"
        ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
        ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service"
        ++ lib.optional ownershipAuthority.enable "aos-sandbox-ownershipd.socket"
        ++ lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
      unitConfig = {
        RequiresMountsFor = ["/sys/fs/cgroup"];
        BindsTo =
          lib.optional policyAuthority.enable "aos-sandbox-cache-journal-view.service"
          ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
          ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service";
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = if cfg.sourceSuccessorIssuance.enable then "oneshot" else "notify";
        SELinuxContext = lib.mkIf (config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0") "system_u:system_r:aos_sandbox_controller_t";
        NotifyAccess = "main";
        ExecStart =
          "${cfg.package}/bin/aos-sandboxd ${toString controller.uid} ${toString controller.gid}"
          + lib.optionalString cfg.publicApi.enable " --public-api"
          + lib.optionalString cfg.publisherIngress.enable " --publisher-ingress"
          + lib.optionalString cfg.gitUploadBootstrap.enable " --git-upload-bootstrap"
          + lib.optionalString cfg.gitReadInspection.enable " --git-read-inspection=${toString config.aos.sandbox.gitGatewayTransport.uid}:${toString config.aos.sandbox.gitGatewayTransport.gid}"
          + lib.optionalString cfg.sourceSuccessorIssuance.enable " --issue-source-successor";
        Sockets = lib.optional cfg.publisherIngress.enable "aos-sandboxd-publisher.socket";
        # Deliver the same configuration-selected inputs independently. Root's
        # original PID1 image never travels to Controller.
        OpenFile =
          lib.optional cfg.method46TpmFloor.required "/proc/1/exe:aos-method46-pid1-image:read-only"
          ++ lib.optional (normalRootProfile != null) "${normalRootProfile}/profile.json:aos-normal-root-client-profile:read-only";
        FileDescriptorStoreMax = lib.mkIf (cfg.method46TpmFloor.required || normalRootProfile != null) 0;
        ExecStartPre = lib.optionals (!cfg.sourceSuccessorIssuance.enable) brokerSessionConfiguration.installCommands;
        LoadCredential =
          nodeCredentials
          ++ cacheReplayCredentials
          ++ cacheReadbackCredentials
          ++ controllerHoldCredentials
          ++ guestRootTemplateCredentials
          ++ brokerPlanCredentials
          ++ mountPlanCredentials
          ++ opensshAttachCredentials
          ++ ownershipCredentials
          ++ brokerSessionConfiguration.loadCredentials
          ++ method46FloorConfiguration.loadCredentials
          ++ publicCredentials
          ++ bootstrapCredentials
          ++ operatorRecoveryCredentials
          ++ publisherScopeCredential
          ++ publisherPolicySourceCredentials
          ++ gitUploadBootstrapCredentials
          ++ projectAuthorizationIssuerCredential
          ++ controllerSourceTreeSeedIssuerCredential
          ++ sourceGenesisPacketCredentials
          ++ sourceSuccessorCredentials;
        Restart = if cfg.sourceSuccessorIssuance.enable then "no" else "on-failure";
        RestartSec = "2s";
        # Population, not cgroup.procs, retains exiting TPM helper tasks until
        # kernel file-release work drains. Never time out that restart barrier.
        ExitType = lib.mkIf cfg.method46TpmFloor.required "cgroup";
        KillMode = lib.mkIf cfg.method46TpmFloor.required "control-group";
        TimeoutStopSec = lib.mkIf cfg.method46TpmFloor.required "infinity";
        TimeoutStartSec = "90s";
        User = "aos-sandboxd";
        Group = "aos-sandboxd";
        StateDirectory = [
          "aos/sandboxd"
          "aos/sandbox/source-domains"
          "aos/sandbox/cache-residency-journals"
          "aos/sandbox/cache-residency-objects"
          "aos/sandboxd/cache-residency-authority"
          "aos/sandboxd/view-sources"
        ];
        StateDirectoryMode = "0700";
        RuntimeDirectory = if cfg.gitReadInspection.enable
          then ["aos/sandboxd" "aos/git-upload-delegation"]
          else "aos/sandboxd";
        # Traversal grants no access to diagnostics or authority; the public
        # socket accepts only registered mutually authenticated TLS clients.
        RuntimeDirectoryMode =
          if cfg.publicApi.enable
          then "0755"
          else "0750";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        DeviceAllow = lib.optional cfg.method46TpmFloor.required "/dev/tpmrm0 rw";
        LimitCORE = 0;
        LimitNOFILE = 128;
        LockPersonality = true;
        MemoryMax = "512M";
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = !cfg.method46TpmFloor.required;
        PrivateNetwork = true;
        PrivateTmp = true;
        # Ordinary protected broker execution guards and original Root/issuer
        # clocks all sample KernelBootId through the read-only sysctl subtree.
        # ProtectKernelTunables and the other confinement settings stay intact.
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        # Selected peers need their exact stat/attr observations. MAC still
        # denies generic foreign task contents; this is not ptrace authority.
        ProtectProc = if cfg.gitReadInspection.enable then "default" else "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 8;
      };
    };

    systemd.services.aos-view-publisher = lib.mkIf cfg.publisherIngress.enable {
      description = "AOS networkless project publisher registration process";
      wantedBy = ["multi-user.target"];
      requires = ["aos-sandboxd.service" "aos-sandboxd-publisher.socket"];
      after = ["aos-sandboxd.service" "aos-sandboxd-publisher.socket"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-view-publisher";
        Restart = "on-failure";
        RestartSec = "2s";
        User = "aos-view-publisher";
        Group = "aos-view-publisher";
        UMask = "0077";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LimitCORE = 0;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 4;
      };
    };
  };
}
