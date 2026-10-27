# Runs the unchanged native assertion driver inside the actual service Main.
{
  pkgs,
  lib,
  mkSystem,
  attrPath,
  kind,
}: let
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  flightSuite = pkgs.crucible.override {privateNativeObservation = true;};
  guest =
    if kind == "four-vcpu"
    then import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;}
    else import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  inputs = import ./_ram-normal-service-inputs.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage;
    nativeFlightKind = kind;
  };
  nativePluginFlight = {
    kind =
      if kind == "four-vcpu"
      then "four_vcpu"
      else "block_recovery";
    kernel = "${inputs}/kernel";
    initrd = "${guest}/initrd.img";
    firmware = "${nativeQemu}/share/qemu/bios-256k.bin";
  };
  deployment = import ./_ram-normal-service-deployment.nix {inherit pkgs lib nativePluginFlight;};
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  store = builtins.toFile "native-plugin-semantic-store.toml" ''
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
  fixtureInputs = {inherit inputs deployment store nativeQemu nativePlugin guest rootImage flightSuite;};
  system = mkSystem {
    modules = [../../systems/server.nix ./_ram-normal-plugin-flight-module.nix];
    specialArgs.normalServiceFixtureInputs = fixtureInputs;
    systemName = "normal-native-plugin-flight";
  };
  service = system.config.aos.crucibleCampaign;
  client = pkgs.writeTextFile {
    name = "normal-native-plugin-client";
    text = import ./_ram-normal-plugin-flight-client.nix {
      inherit pkgs lib service kind;
      attemptFile = "${inputs}/attempt-id";
    };
  };
  installedInputs = "/var/lib/crucible-campaign/normal-inputs";
in
  assert builtins.elem kind ["four-vcpu" "block-recovery"];
    import ./ram-native-flight.nix {
      inherit pkgs lib attrPath nativeQemu nativePlugin;
      normalServiceConfig = system.config;
      pname = "crucible-normal-native-plugin-${kind}";
      gateId = "gate:production-rust-plugin-flight";
      testName = "";
      successMarker = "NORMAL_PLUGIN_FLIGHT_PASS";
      lanes = ["plugin-four" "plugin-block"];
      outerCpuSlots = 6;
      outerMemoryMiB = 12288;
      writableMiB = 32768;
      storageImageBytes = 17179869184;
      # Preserve the existing plugin flight outer watchdog and disk envelopes.
      outerTimeoutSeconds = 6000;
      innerTimeoutSeconds = 1800;
      evidencePrefix = "normal_plugin";
      innerPreparation = ''
        ${pkgs.coreutils}/bin/mkdir -m 700 -p ${installedInputs} \
          /var/paging-storage/semantic /var/paging-storage/run /var/paging-storage/lifecycle
        ${pkgs.coreutils}/bin/cp -R ${inputs}/state/. /var/paging-storage/semantic/
        ${pkgs.coreutils}/bin/chmod -R u+rwX,go-rwx /var/paging-storage/semantic
        for input in component-authority.bin ca.pem server.pem server.key client.pem client.key; do
          ${pkgs.coreutils}/bin/cp ${inputs}/"$input" ${installedInputs}/"$input"
          ${pkgs.coreutils}/bin/chmod 600 ${installedInputs}/"$input"
        done
        ${quotaInstaller}/bin/install-catalog-quota \
          /var/paging-storage /var/paging-storage/ram-catalogs 36000 1073741824 262144
        ${quotaInstaller}/bin/install-catalog-quota \
          /var/paging-storage /var/paging-storage/executor-ledger 36001 16777216 65536
      '';
      innerInvocation = _: "${pkgs.bash}/bin/bash ${client}";
      extraRootfsDeps = [inputs deployment store quotaInstaller client flightSuite pkgs.jq pkgs.grep];
      innerEvidence = {buildGraph}: ''
        echo normal_plugin_build_graph=${buildGraph}
        echo normal_plugin_main_elf=${flightSuite.passthru.controller}/bin/crucible
      '';
      outerEvidence = _: ''
        test "$(${pkgs.grep}/bin/grep -Fxc 'production_accepted_assignment=true' "$out/serial.log")" -eq 1
      '';
    }
