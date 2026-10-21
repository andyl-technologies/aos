##! Checks image-budget and boot-storage assertions through their real modules.
{
  pkgs,
  lib,
}: let
  evaluateFor = cpu: rootPartitionMiB: extraModule:
    lib.evalModules {
      inherit lib;
      checkDefinitionPaths = [["aos" "image" "budgets"]];
      pkgs.stdenv.hostPlatform.constraints = {inherit cpu;};
      modules = [
        ../../modules/image/default.nix
        ../../modules/base/boot-storage.nix
        extraModule
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          options.aos.filesystems.espDevice = lib.mkOption {
            type = lib.types.str;
          };
          aos.image.rootPartitionMiB = rootPartitionMiB;
        }
      ];
    };
  failedMessages = evaluation:
    builtins.map (assertion: assertion.message)
    (builtins.filter (assertion: !assertion.assertion) evaluation.config.assertions);
  healthy = evaluateFor "x86_64" 1024 {};
  undersized = evaluateFor "x86_64" 511 {};
  foreign = evaluateFor "aarch64" 1024 {};
  staleBudgetNames = evaluateFor "x86_64" 1024 {
    aos.image.budgets = {
      maxUkiMiB = 256;
      maxEspMiB = 736;
    };
  };
  expandedBudgets = evaluateFor "x86_64" 1024 {
    aos.image.budgets = {
      maxBootExecutableMiB = 256;
      maxFirmwarePartitionMiB = 736;
    };
  };
  checks = [
    {
      ok = !(builtins.tryEval (builtins.deepSeq staleBudgetNames.config.aos.image.budgets true)).success;
      message = "stale image budget names must fail instead of silently retaining defaults";
    }
    {
      ok =
        failedMessages expandedBudgets
        == []
        && expandedBudgets.config.aos.image.budgets.maxBootExecutableMiB == 256
        && expandedBudgets.config.aos.image.budgets.maxFirmwarePartitionMiB == 736;
      message = "declared boot executable and firmware budget overrides must remain effective";
    }
    {
      ok =
        healthy.config.aos.image.budgets.maxInitrdMiB
        == 160
        && healthy.config.aos.image.budgets.maxBootExecutableMiB == 160
        && healthy.config.aos.image.budgets.maxFirmwarePartitionMiB == 384
        && healthy.config.aos.image.budgets.maxRuntimeClosureMiB == 768;
      message = "x86 image defaults must retain the baseline boot and runtime allowances";
    }
    {
      ok =
        foreign.config.aos.image.budgets.maxInitrdMiB
        == 160
        && foreign.config.aos.image.budgets.maxBootExecutableMiB == 192
        && foreign.config.aos.image.budgets.maxFirmwarePartitionMiB == 416
        && foreign.config.aos.image.budgets.maxRuntimeClosureMiB == 896;
      message = "AArch64 image defaults must accommodate the uncompressed kernel and runtime closure";
    }
    {
      ok = failedMessages healthy == [];
      message = "healthy image geometry must satisfy image and storage assertions";
    }
    {
      ok =
        builtins.elem
        "aos.image.rootPartitionMiB must be at least aos.image.budgets.maxRootMiB"
        (failedMessages undersized);
      message = "undersized root partition must be rejected";
    }
    {
      ok =
        builtins.elem
        "ZFS root slot capacity must be at least the image root artifact budget"
        (failedMessages undersized);
      message = "undersized default ZFS slot must be rejected";
    }
    {
      ok = undersized.config.aos.boot.storage.zfs.rootSlotSizeMiB == 511;
      message = "root partition override must feed the default ZFS slot capacity";
    }
  ];
  checked =
    builtins.foldl' (result: check:
      lib.throwIfNot check.ok check.message result)
    true
    checks;
in
  pkgs.mkDerivation {
    pname = "aos-image-assertion-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          : ${builtins.toString checked}
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
