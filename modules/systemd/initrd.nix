##! modules/systemd/initrd.nix — Stage 1 systemd module (tier i)
##!
##! Declares the typed `boot.initrd.systemd.*` option tree for a
##! future systemd-based initrd. Uses the `stage1*` option + type
##! variants from `_unit-options.nix` / `_types.nix`, so modules that
##! contribute initrd units declare them with real per-option
##! validation exactly like stage-2 services.
##!
##! **This is tier (i) per spec §11.3: type-level only.** No builder.
##! `system.build.initrd` stays as the placeholder in
##! `modules/base/build.nix`; modules can set
##! `boot.initrd.systemd.services.<name>` today and the definitions
##! will round-trip through `evalModules` with proper type checking,
##! but the resulting config is not yet consumed by anything. When
##! the real initrd builder lands (tier ii, §11.3), it will read from
##! this option tree and produce a systemd initrd image at the
##! `system.build.initrd` path.
##!
##! Until then, this module exists so:
##!   1. Modules like `modules/services/ignition.nix` can be migrated
##!      from `systemd.services.*` (where they don't actually run,
##!      see §6.11) to `boot.initrd.systemd.services.*` (where they
##!      also don't run yet, but the structure is correct and the
##!      migration is a one-line option-path rename when tier ii
##!      lands).
##!   2. The ported type tree is actually exercised for stage 1, so
##!      any divergence between `stage1*` and `stage2*` options shows
##!      up at eval time rather than during the tier-ii port.
{
  config,
  lib,
  pkgs,
  ...
}: let
  systemdLib = import ./_lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ./_unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ./_types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };
in {
  options.boot.initrd.systemd = {
    enable = lib.mkEnableOption "a systemd-based initrd (tier ii, not yet implemented)";

    services = lib.mkOption {
      type = systemdTypes.initrdServices;
      default = {};
      description = ''
        Typed .service units to include in the systemd initrd. Same
        option tree as the stage-2 `systemd.services`, minus the
        stage-2-specific switch-to-configuration knobs (`startAt`,
        `restartIfChanged`, …). No builder consumes this yet;
        contributions are type-checked at eval time for future use.
      '';
    };

    targets = lib.mkOption {
      type = systemdTypes.initrdTargets;
      default = {};
      description = "Typed .target units to include in the systemd initrd.";
    };

    sockets = lib.mkOption {
      type = systemdTypes.initrdSockets;
      default = {};
      description = "Typed .socket units to include in the systemd initrd.";
    };

    timers = lib.mkOption {
      type = systemdTypes.initrdTimers;
      default = {};
      description = "Typed .timer units to include in the systemd initrd.";
    };

    paths = lib.mkOption {
      type = systemdTypes.initrdPaths;
      default = {};
      description = "Typed .path units to include in the systemd initrd.";
    };

    slices = lib.mkOption {
      type = systemdTypes.initrdSlices;
      default = {};
      description = "Typed .slice units to include in the systemd initrd.";
    };

    mounts = lib.mkOption {
      type = systemdTypes.initrdMounts;
      default = [];
      description = "Typed .mount units to include in the systemd initrd. Keyed by `where`, not by name.";
    };

    automounts = lib.mkOption {
      type = systemdTypes.initrdAutomounts;
      default = [];
      description = "Typed .automount units to include in the systemd initrd. Keyed by `where`, not by name.";
    };
  };

  # No config block. When the tier-ii initrd builder arrives, this
  # module will grow a `config = { system.build.initrd = ...; };`
  # block that reads the option tree and produces a real initrd.
  # See spec §11.3 for the sketch of what that builder should do.
}
