# Source-backed normal service settings for the existing disposable kernel VM.
# These builder inputs identify actual files; the Main still authenticates its
# real manager and admits the unchanged resources before execution.
{
  lib,
  normalServiceFixtureInputs,
  ...
}: let
  inherit (normalServiceFixtureInputs) inputs deployment store nativeQemu nativePlugin guest rootImage;
  installedInputs = "/var/lib/crucible-campaign/normal-inputs";
in {
  aos.crucibleCampaign = {
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
}
