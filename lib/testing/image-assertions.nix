##! Checks image-budget and boot-storage assertions through their real modules.
{
  pkgs,
  lib,
}: let
  evaluate = rootPartitionMiB:
    lib.evalModules {
      inherit lib;
      pkgs = {};
      modules = [
        ../../modules/image/default.nix
        ../../modules/base/boot-storage.nix
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
  healthy = evaluate 1024;
  undersized = evaluate 511;
  checks = [
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
