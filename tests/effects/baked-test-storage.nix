##! Matches completed fleet disks to their package-owned provisioning defaults.
{
  lib,
  pkgs,
}: let
  layoutFor = import ../../pkgs/system/_systemd-abilities/testing/storage-layout.nix;
  layout = layoutFor {varSizeMiB = 2048;};
  machineModule = import ../../pkgs/system/_systemd-abilities/testing/fleet-module.nix {
    inherit lib;
    packages = {inherit (pkgs) bash coreutils systemd;};
  };
  machine = mode: provisioning:
    (machineModule {
      bootMode = mode;
      varProvisioning = provisioning;
      varSizeMiB = 2048;
      bakeAgentUnit = false;
      debugMac = "52:54:00:12:34:57";
      mac = "52:54:00:12:34:56";
      ip = "192.0.2.5";
      defaultAgentPackage = pkgs.aos-test-agent;
      inherit (pkgs) writeTextFile;
    }) {config.aos.packages = {};};
  sources = mode: provisioning: (machine mode provisioning).aos.activation.stages.host.configuration;
  evaluate = configuration:
    (lib.evalPackageModules {
      packages = [pkgs.aos-host-policy pkgs.systemd pkgs.aos-storage-provisioning-provider];
      scope = ["test" "baked-storage"];
      operatorModules = configuration;
    }).config.aos.provisioning.storage.partitions;
  production = evaluate [];
  baked = evaluate (sources "kernel" "baked");
  operator = evaluate ((sources "kernel" "baked")
    ++ [
      {
        aos.provisioning.storage.partitions.var = {
          sizeMin = "3072M";
          sizeMax = "4096M";
          grow = true;
        };
      }
    ]);
  payload = toString (import ./_fixture-payload.nix "baked-storage-tools");
  capture = arguments: arguments // {outPath = payload;};
  buildDisk = import ../../pkgs/system/_systemd-abilities/testing/disk.nix {
    inherit lib;
    closureInfoFor = _: {outPath = payload;};
    packages = {
      mkDerivation = capture;
      writeTextFile = capture;
      openssh = payload;
      swtpm = payload;
      runCommand = _: _: _: {outPath = payload;};
    };
  };
  script =
    (builtins.head
      (buildDisk {
        system = {};
        varSizeMiB = 2048;
      }).phases).script;
  contains = text: needle: builtins.length (lib.splitString needle text) > 1;
in {
  productionDefaultsUnchanged = production.swap.sizeMin == "2G" && production.swap.sizeMax == "2G" && production.var.sizeMin == "4G" && production.var.sizeMax == null && production.var.grow;
  swapMatchesBakedDisk = baked.swap.sizeMin == "${toString layout.swapSizeMiB}M" && baked.swap.sizeMax == baked.swap.sizeMin && !baked.swap.grow;
  varMatchesBakedDisk = baked.var.sizeMin == "${toString layout.varSizeMiB}M" && baked.var.sizeMax == baked.var.sizeMin && !baked.var.grow;
  assemblyUsesSharedSizes = contains script "VAR_SIZE_MIB=${toString layout.varSizeMiB}" && contains script "SWAP_SECTORS=$(( ${toString layout.swapSizeMiB} * 1024 * 1024 / 512 ))";
  sshHostKeysUseNativeFirstBoot = !(contains script "mkdir -p var/etc/ssh") && !(contains script "ssh_host_ed25519_key") && !(contains script "/bin/ssh-keygen");
  retainedPolicyIsShared = builtins.elem layout.configurationSource (sources "kernel" "baked");
  imageBootDoesNotRetainPolicy = sources "image" "baked" == [];
  repartDoesNotRetainPolicy = !(builtins.elem layout.configurationSource (sources "kernel" "repart")) && (layoutFor {varProvisioning = "repart";}).configurationSource == null;
  authoredPolicyOverridesFixture = operator.var.sizeMin == "3072M" && operator.var.sizeMax == "4096M" && operator.var.grow;
  invalidSizeRejected = !(builtins.tryEval (layoutFor {varSizeMiB = 0;}).baked).success;
  invalidModeRejected = !(builtins.tryEval (layoutFor {varProvisioning = "unknown";}).baked).success;
}
