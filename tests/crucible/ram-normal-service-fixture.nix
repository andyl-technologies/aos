# Genuine packaged Main and external-client controls in the existing kernel VM.
{
  pkgs,
  lib,
  mkSystem,
  attrPath,
}: let
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  productionFlight = import ./phase7-production-rust-plugin-flight.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase7.raw.productionPluginFlight";
  };
  guest = productionFlight.passthru.idleGuest;
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  inputs = import ./_ram-normal-service-inputs.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage;
  };
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  deployment = import ./_ram-normal-service-deployment.nix {inherit lib;};
  installedInputs = "/var/lib/crucible-campaign/normal-inputs";
  store = builtins.toFile "normal-ram-semantic-store.toml" ''
    schema = "crucible.campaign-repository-store"
    version = 3
    root = "semantic"
    admitted_kinds = ["campaign-fact", "campaign-snapshot", "merkle-node", "scenario", "configuration", "policy", "exact-manifest", "ram-extent", "disk-extent", "device-state", "observation", "finding", "projection", "trace"]
    ref_directory = "/var/paging-storage/semantic/refs"
    [[nodes]]
    id = "semantic"
    [nodes.spec]
    kind = "directory"
    root = "/var/paging-storage/semantic/objects"
  '';
  serviceModule = {
    aos.services.crucibleCampaign = {
      enable = true;
      processResources = {
        # This is an explicit disposable policy authenticated by real PID1.
        # It is separate from evaluation examples and remains below the outer 4 GiB.
        memoryMaxBytes = 3221225472;
        baselineResidentBytes = 536870912;
        metadataBytes = 805306368;
        sqliteBootstrapBytes = 8388608;
        sqliteHeapBytes = 8388608;
        sqliteConnections = 4;
        tasksMax = 256;
        fileDescriptors = 4096;
        baselineFileDescriptors = 128;
        cpuQuotaPercent = 400;
        runtimeSeconds = 2700;
        startupTimeoutSeconds = 120;
        mainThreadStackBytes = 1048576;
        threadStackBytes = 1048576;
        workerThreads = 4;
        blockingThreads = 8;
      };
      executor = {
        deploymentFile = deployment;
        socketPath = "/run/crucible-campaign/executor.sock";
        campaigns = ["normal-ram"];
        userfaultfdGroupId = 29000;
        repositoryStoreFile = store;
        componentAuthorityFile = "${installedInputs}/component-authority.bin";
        importManifests = ["${inputs}/import.toml"];
        transport = {
          serverCertificateFile = "${installedInputs}/server.pem";
          serverKeyFile = "${installedInputs}/server.key";
          clientCaFile = "${installedInputs}/ca.pem";
          # Read the real builder's certificate digest, never a fabricated
          # permission token. This input derivation must finish before VM birth.
          operatorCertificateFingerprints = [
            (lib.removeSuffix "\n" (builtins.readFile "${inputs}/client.fingerprint"))
          ];
        };
        guestAssets = {
          qemu = "${nativeQemu}/bin/qemu-system-x86_64";
          plugin = "${nativePlugin}/lib/libcrucible_qemu_plugin.so";
          kernel = "${inputs}/kernel";
          rootImage = "${rootImage}/root.ext4";
          initrd = "${guest}/initrd.img";
          architecture = "x86_64";
          kernelCommandLine = "";
          runStateRoot = "/var/paging-storage/lifecycle";
        };
      };
    };
  };
  preparation = ''
    ${pkgs.coreutils}/bin/mkdir -m 700 -p \
      ${installedInputs} /var/paging-storage/semantic \
      /var/paging-storage/run /var/paging-storage/lifecycle
    ${pkgs.coreutils}/bin/cp -R ${inputs}/state/. /var/paging-storage/semantic/
    ${pkgs.coreutils}/bin/chmod -R u+rwX,go-rwx /var/paging-storage/semantic
    for input in component-authority.bin ca.pem server.pem server.key client.pem client.key; do
      ${pkgs.coreutils}/bin/cp ${inputs}/"$input" ${installedInputs}/"$input"
      ${pkgs.coreutils}/bin/chmod 600 ${installedInputs}/"$input"
    done
    ${quotaInstaller}/bin/install-catalog-quota \
      /var/paging-storage /var/paging-storage/ram-catalogs 36000 536870912 262144
    ${quotaInstaller}/bin/install-catalog-quota \
      /var/paging-storage /var/paging-storage/executor-ledger 36001 16777216 65536
  '';
in
  import ./ram-normal-service.nix {
    inherit pkgs lib mkSystem attrPath serviceModule nativeQemu nativePlugin preparation;
    campaign = "normal-ram";
    attemptFile = "${inputs}/attempt-id";
    clientAuthorityFile = "${installedInputs}/ca.pem";
    clientCertificateFile = "${installedInputs}/client.pem";
    clientKeyFile = "${installedInputs}/client.key";
    idempotencyKey = builtins.concatStringsSep "" (builtins.genList (_: "63") 32);
    inputDependencies = [inputs deployment store quotaInstaller];
  }
