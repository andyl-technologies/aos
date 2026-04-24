# lib/testing/ignition-format.nix — Regression guard for the typed
# Ignition v3.6 config format.
#
# Covers:
#   1. A minimal valid Ignition config under the test-harness profile
#      (allowStorageHardware = false) evaluates cleanly.
#   2. Setting `storage.disks` / `storage.filesystems` under that
#      profile throws at eval time — the opt-in strict mode of the
#      underlying submodule is what enforces this, not ignition-validate
#      (which silently accepts unknown JSON fields).
#   3. The full schema (`allowStorageHardware = true`) accepts the same
#      storage-hardware fields, demonstrating that the rejection is
#      about profile scoping and not a global restriction.
#
# Runs via `nix-build -A checks.ignition-format`.
{
  pkgs,
  lib,
}: let
  testFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };

  fullFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = true;
  };

  mkEval = format: cfg:
    lib.evalModules {
      modules = [
        {
          options.cfg = lib.mkOption {
            type = format.type;
            default = {};
          };
        }
        {config.cfg = cfg;}
      ];
    };

  tryEvalCfg = format: cfg:
    builtins.tryEval (
      builtins.deepSeq (mkEval format cfg).config.cfg null
    );

  # --- 1. Minimal valid config evaluates cleanly. -----------------------
  minimalOk =
    (tryEvalCfg testFormat {
      ignition.version = "3.5.0";
      storage.directories = [{path = "/var/etc";}];
      storage.files = [
        {
          path = "/var/etc/hostname";
          mode = 420;
          overwrite = true;
          contents.source = "data:,test";
        }
      ];
    })
    .success;

  # --- 2. Test profile rejects storage.disks / storage.filesystems. -----
  disksRejected =
    !(tryEvalCfg testFormat {
      ignition.version = "3.5.0";
      storage.disks = [
        {
          device = "/dev/vda";
          partitions = [{number = 3;}];
        }
      ];
    })
    .success;

  filesystemsRejected =
    !(tryEvalCfg testFormat {
      ignition.version = "3.5.0";
      storage.filesystems = [
        {
          device = "/dev/disk/by-partlabel/var";
          format = "ext4";
        }
      ];
    })
    .success;

  # --- 3. Full profile accepts those same fields. -----------------------
  disksAccepted =
    (tryEvalCfg fullFormat {
      ignition.version = "3.5.0";
      storage.disks = [
        {
          device = "/dev/vda";
          partitions = [{number = 3;}];
        }
      ];
    })
    .success;

  filesystemsAccepted =
    (tryEvalCfg fullFormat {
      ignition.version = "3.5.0";
      storage.filesystems = [
        {
          device = "/dev/disk/by-partlabel/var";
          format = "ext4";
        }
      ];
    })
    .success;

  allOk =
    lib.throwIfNot minimalOk
    "ignition-format: minimal valid test config failed to evaluate"
    (lib.throwIfNot disksRejected
      "ignition-format: test profile should reject storage.disks"
      (lib.throwIfNot filesystemsRejected
        "ignition-format: test profile should reject storage.filesystems"
        (lib.throwIfNot disksAccepted
          "ignition-format: full profile should accept storage.disks"
          (lib.throwIfNot filesystemsAccepted
            "ignition-format: full profile should accept storage.filesystems"
            true))));
in
  pkgs.mkDerivation {
    pname = "ignition-format-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString allOk}
          echo "==> ignition-format regression check"
          echo "  test profile — minimal config evaluates: OK"
          echo "  test profile — storage.disks rejected: OK"
          echo "  test profile — storage.filesystems rejected: OK"
          echo "  full profile — storage.disks accepted: OK"
          echo "  full profile — storage.filesystems accepted: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib.formats.ignition typing";
  }
