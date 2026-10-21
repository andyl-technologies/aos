# Signed installed-system qualification with finite prepaid startup envelopes.
# External credential names are reserved for guest-side provisioning. This image
# policy neither provisions credentials nor grants an operation or effect.
{
  lib,
  pkgs,
  systems,
}:
systems.server-secureboot-lockdown.extendModules {
  modules = [
    ../../systems/_server-test-packages.nix
    ({config, ...}: let
      mib = 1048576;
      gib = 1024 * mib;
      vector = values: lib.genAttrs config.aos.sandbox.resourceBank._dimensionOrder (name: values.${name} or 0);
      envelope = memory: cpu: pids: files:
        vector {
          memory-bytes = memory;
          cpu-micros-per-period = cpu;
          inherit pids;
          open-files = files;
          concurrent-operations = pids;
          metadata-entries = memory / 4096;
          mapped-index-bytes = memory / 16;
          log-bytes = memory / 8;
          mounts = pids * 16;
        };
      sharedCredential = name: "qualification-${name}";
      sessionCredentials = lib.listToAttrs (lib.concatMap (endpoint:
        map (suffix: {
          name = "brokerSession${endpoint}${suffix}";
          value = sharedCredential "${endpoint}-${suffix}";
        }) ["Manifest" "HelloKey" "RecordKey"])
      ["Host" "Storage" "Mount" "Network"]);
    in {
      aos.image = {
        allowTestArtifacts = true;
        # Match the full-service test image's A/B slots and fast compression.
        # These fixtures include every online Controller and broker closure.
        erofsCompressionLevel = 1;
        rootPartitionMiB = 2048;
        budgets = {
          maxRuntimeClosureMiB = lib.mkForce 8192;
          maxRootMiB = 1536;
          maxDownloadMiB = 2048;
          maxConvertedDownloadMiB = 2048;
          # The signed stage-one archive measures 240.61 MiB before its kernel
          # and boot executable. Retain two normal and three recovery slots.
          maxInitrdMiB = 256;
          maxBootExecutableMiB = 288;
          maxFirmwarePartitionMiB = 832;
        };
      };
      aos.boot.kernelParams = ["systemd.log_level=info" "rd.systemd.log_level=info" "systemd.log_target=journal-or-kmsg"];

      aos.boot.initrd.stage0 = lib.mkForce (pkgs.aosSelinuxStage0With {
        aos-selinux-production-policy = config.aos.security.selinux._productionPolicy;
        aos-selinux-runtime-roots = config.aos.security.selinux._runtimeRootsProvisioner;
        admissionUnit = "";
        expectedPolicy = "${config.aos.security.selinux._canonicalReadback}/policy.33";
        expectedPolicyKernel = config.system.build.kernel;
      });

      aos.security.selinux = {
        _qualificationAdmissionRelease = true;
        enable = true;
        bootMode = "immutable-stage0";
      };
      aos.sandbox = {
        controllerService = {
          enable = true;
          credentials =
            sessionCredentials
            // {
              nodeId = sharedCredential "node-id";
              brokerPlanSigningKey = sharedCredential "broker-plan-signing-key";
            };
        };
        hostBroker = {
          enable = true;
          componentControl = true;
          credentials = {
            ownershipLeasePolicy = sharedCredential "ownership-lease-policy.cbor";
            ownershipLeasePublicKey = sharedCredential "ownership-lease-public-key";
            nodeId = sharedCredential "node-id";
            journalMacKey = sharedCredential "host-journal-mac-key";
            brokerPlanPolicy = sharedCredential "broker-plan-policy.cbor";
            brokerPlanPublicKey = sharedCredential "broker-plan-public-key";
            brokerRevocationScope = sharedCredential "broker-revocation-scope";
          };
        };
        storageBroker.enable = true;
        storageWorker.enable = true;
        mountBroker = {
          enable = true;
          credentials = {
            ownershipLeasePolicy = sharedCredential "ownership-lease-policy.cbor";
            ownershipLeasePublicKey = sharedCredential "ownership-lease-public-key";
            nodeId = sharedCredential "node-id";
            journalMacKey = sharedCredential "mount-journal-mac-key";
            brokerPlanPolicy = sharedCredential "mount-broker-plan-policy.cbor";
            brokerPlanPublicKey = sharedCredential "mount-broker-plan-public-key";
            brokerRevocationScope = sharedCredential "mount-broker-revocation-scope";
          };
        };
        networkBroker.enable = true;
        networkWorker.enable = true;
        ownershipAuthority = {
          enable = true;
          credentials = {
            sessionKey = sharedCredential "ownership-session-key";
            signingKey = sharedCredential "ownership-signing-key";
          };
        };
        nixBroker = {
          enable = true;
          builderUid = 819;
          builderGid = 819;
          domainIdHex = "33333333333333333333333333333333";
          publicCredentials =
            lib.genAttrs [
              "nix-recipe-issuer-v2"
              "nix-fixed-domain-pins-v2"
              "nix-broker-session-manifest-v1"
              "nix-preadmitted-recipes-v2"
              "ownership-lease-policy.cbor"
              "ownership-lease-public-key"
              "broker-plan-policy.cbor"
              "broker-plan-public-key"
              "broker-revocation-scope"
              "mount-broker-plan-policy.cbor"
              "mount-broker-plan-public-key"
              "mount-broker-revocation-scope"
            ]
            sharedCredential;
          controllerFloor = {
            issuer = sharedCredential "nix-controller-issuer";
            auth = sharedCredential "nix-controller-auth";
            genesis = sharedCredential "nix-controller-genesis";
          };
          ownerFloor = {
            issuer = sharedCredential "nix-owner-issuer";
            auth = sharedCredential "nix-owner-auth";
            genesis = sharedCredential "nix-owner-genesis";
          };
          storeSnapshot = sharedCredential "nix-store-snapshot";
          credentials = lib.genAttrs ["manifest" "hello" "record" "clientManifest" "clientHello" "clientRecord"] (name: sharedCredential "nix-session-${name}");
        };
        policyAuthority = {
          enable = true;
          credentials = {
            backendCapabilities = sharedCredential "root-backendCapabilities";
            catalogs = sharedCredential "root-catalogs";
            deploymentHeadPacket = sharedCredential "root-deploymentHeadPacket";
            deploymentPublicKey = sharedCredential "root-deploymentPublicKey";
            nodePolicy = sharedCredential "root-nodePolicy";
            projectPublicKey = sharedCredential "root-projectPublicKey";
            sitePolicy = sharedCredential "root-sitePolicy";
            projectHeadPacketV2 = sharedCredential "root-projectHeadPacketV2";
            projectLayerV2 = sharedCredential "root-projectLayerV2";
            sourceHoldPublicKey = sharedCredential "source-hold-public-key";
          };
        };
        sourceSignerView.enable = true;
        sourceSignerService = {
          enable = true;
          credentials = {
            seed = sharedCredential "source-private-seed";
            publicKey = sharedCredential "source-hold-public-key";
          };
        };
        cacheSignerService.credentials.memoryCeiling = sharedCredential "cache-memory-ceiling";
        resourceBank = {
          policy = {
            node = "11111111111111111111111111111111";
            epoch = "22222222222222222222222222222222";
            capacity = vector (lib.genAttrs config.aos.sandbox.resourceBank._dimensionOrder (_: 1073741824)
              // {
                memory-bytes = 32 * gib;
                cpu-micros-per-period = 1600000;
                storage-bytes = 32 * gib;
                log-bytes = 4 * gib;
                mapped-index-bytes = 4 * gib;
              });
            baseline = envelope gib 200000 128 65536;
            controller =
              (envelope (8 * gib) 400000 64 131072)
              // {
                metadata-entries = 16 * mib;
                publication-staging-bytes = 128 * mib;
                output-bytes = 128 * mib;
              };
            components = envelope (16 * gib) 1000000 512 1048576;
            hostService = envelope (512 * mib) 100000 32 8192;
            hostControl = envelope (128 * mib) 10000 8 512;
            firstGlobalPrefix = envelope (256 * mib) 10000 1 4096;
            nixOriginalStartIntake = envelope (256 * mib) 10000 1 4096;
            q04OriginalIntake =
              (envelope (256 * mib) 10000 1 4096)
              // {
                metadata-entries = 2 * mib;
                publication-staging-bytes = 2 * mib;
                output-bytes = 2 * mib;
              };
            rootReceiving = envelope gib 100000 32 8192;
            createContinuationIntake =
              (envelope (256 * mib) 10000 1 4096)
              // {
                metadata-entries = 2 * mib;
                publication-staging-bytes = 2 * mib;
                output-bytes = 2 * mib;
              };
            storageReceiving = envelope (2 * gib) 100000 64 8192;
          };
          parentEnclosure = {
            manager = envelope (4 * gib) 100000 64 65536;
            fixedServices = envelope (4 * gib) 300000 128 131072;
            sourceSignerSender = envelope (128 * mib) 1000 1 128;
            sourceSignerReceiving = envelope (512 * mib) 50000 8 256;
            ownershipSender = envelope (128 * mib) 1000 1 128;
            ownershipReceiving = envelope (256 * mib) 25000 8 256;
            mountSender = envelope (128 * mib) 1000 1 128;
            mountReceiving = envelope (256 * mib) 25000 8 256;
            networkSender = envelope (128 * mib) 1000 1 128;
            networkReceiving = envelope (256 * mib) 25000 8 256;
            managerOpenFilesPerProcess = 1024;
            # Each receiver has 256 descriptors total, including the actual
            # inherited pre-exec peak as well as this new process table.
            fixedOpenFilesPerProcess = 128;
            journal = {
              systemMaxUse = 64 * mib;
              systemMaxFileSize = 8 * mib;
              runtimeMaxUse = 64 * mib;
              runtimeMaxFileSize = 8 * mib;
            };
            audit = {
              maxLogFileMiB = 8;
              numLogs = 2;
              maximumRules = 64;
              maximumRuleBytes = 65536;
              maximumBacklog = 8192;
            };
          };
        };
      };
    })
  ];
}
