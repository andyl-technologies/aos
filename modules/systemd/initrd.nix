##! modules/systemd/initrd.nix — Stage 1 systemd module (tier ii)
##!
##! Declares the typed `boot.initrd.systemd.*` option tree for the
##! systemd-based initrd and produces `system.build.initrd` by
##! rendering the options through the stage-1 `*-ToUnit` helpers in
##! `lib/modules/systemd/lib.nix` and piping the result through
##! `generateUnits` and then into the cpio assembler in
##! `../base/initrd-builder.nix`.
##!
##! Uses the `stage1*` option + type variants from
##! `lib/modules/systemd/unit-options.nix` / `lib/modules/systemd/types.nix`,
##! so modules that contribute initrd units declare
##! them with real per-option validation exactly like stage-2 services.
##! The stage-1 option trees drop the switch-to-configuration knobs
##! (`startAt`, `restartIfChanged`, ...) and otherwise mirror the
##! stage-2 options.
##!
##! Unlike stage 2 (`system.nix`), this module does NOT fold the
##! rendered units into a shared `systemd.units` attrset — the stage-2
##! and stage-1 renderers produce a parallel set each, and the initrd
##! has its own generateUnits invocation with `type = "initrd"`.
##!
##! Outputs (wired by the `config` block below):
##!   * `system.build.systemdInitrdUnits` — directory matching
##!     `/etc/systemd/system/` for the initrd, produced by
##!     `generateUnits`. Consumed by the initrd builder.
##!   * `system.build.initrd` — the final gzip+cpio initramfs
##!     derivation produced by `../base/initrd-builder.nix`.
{
  config,
  lib,
  pkgs,
  ...
}: let
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../../lib/modules/systemd/unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ../../lib/modules/systemd/types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };

  cfg = config.boot.initrd.systemd;

  # Render each initrd unit category through its stage-1 *-ToUnit
  # renderer and key the result by unit file name (e.g. "foo.service").
  # Mirrors `modules/systemd/system.nix`'s stage-2 pattern but without
  # the `globalEnvironment` pre-merge — initrd services don't need it.
  #
  # The *-ToUnit renderers return `{ name; text; wantedBy; ...; }`
  # without a `.unit` attribute; stage-2 relies on the `systemd.units`
  # submodule type to run each entry through `makeUnit` and populate
  # `.unit`. The initrd has no matching option tree so we call
  # `makeUnit` ourselves — generateUnits reads `.unit` below.
  withUnitDrv = entry: entry // {unit = systemdLib.makeUnit entry.name entry;};
  withName = cfgToUnit: c: lib.nameValuePair c.name (withUnitDrv (cfgToUnit c));
  renderedInitrdUnits =
    lib.mapAttrs' (_: withName systemdLib.serviceToUnit) cfg.services
    // lib.mapAttrs' (_: withName systemdLib.targetToUnit) cfg.targets
    // lib.mapAttrs' (_: withName systemdLib.socketToUnit) cfg.sockets
    // lib.mapAttrs' (_: withName systemdLib.timerToUnit) cfg.timers
    // lib.mapAttrs' (_: withName systemdLib.pathToUnit) cfg.paths
    // lib.mapAttrs' (_: withName systemdLib.sliceToUnit) cfg.slices
    // lib.listToAttrs (builtins.map (withName systemdLib.mountToUnit) cfg.mounts)
    // lib.listToAttrs (builtins.map (withName systemdLib.automountToUnit) cfg.automounts);
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

    maskedUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Unit names to mask (symlink to /dev/null) in the initrd.
        Needed because the initrd's /usr→. symlink collapses systemd's
        unit search priority, making kernel-cmdline systemd.mask=
        ineffective.
      '';
    };
  };

  # Declare `system.build.systemdInitrdUnits` as a real option so the
  # initrd builder below (and any out-of-tree consumers) can read it.
  options.system.build.systemdInitrdUnits = lib.mkOption {
    type = lib.types.package;
    description = ''
      Derivation whose output is an assembled `/etc/systemd/system/`
      directory for the initrd — produced by `generateUnits` over the
      rendered `boot.initrd.systemd.*` option tree. Consumed by the
      cpio assembler in `modules/base/initrd-builder.nix`.
    '';
  };

  config = {
    # Stage-1 runs with an empty /etc (just /etc/os-release and a few
    # basics from the cpio builder), so systemd-sysctl and
    # systemd-tmpfiles read no config and exit successfully with
    # nothing to do. systemd then serializes the "done" state across
    # initrd→rootfs switch-root and stage-2 never re-runs them — so the
    # real /etc/sysctl.d/* and /etc/tmpfiles.d/* on the rootfs are
    # silently ignored. Mask both in the initrd to force stage-2 to run
    # them fresh against the real /etc.
    boot.initrd.systemd.maskedUnits = [
      "systemd-sysctl.service"
      "systemd-tmpfiles-setup.service"
      "systemd-tmpfiles-setup-dev.service"
    ];

    system.build.systemdInitrdUnits = systemdLib.generateUnits {
      type = "initrd";
      units = renderedInitrdUnits;
      # AOS stage-1 symlinks upstream systemd units inside the cpio
      # builder itself (it reads them directly from
      # `${systemd}/lib/systemd/system/`). `generateUnits` would look
      # under `$package/example/systemd/`, which AOS does not
      # populate — see the TODO at `lib/modules/systemd/lib.nix:510`.
      upstreamUnits = [];
      upstreamWants = [];
      packages = [];
    };

    system.build.initrd = import ../base/_initrd-builder.nix {
      inherit pkgs lib;
      kernel = config.system.build.kernel;
      kernelModules = config.aos.boot.initrd.modules;
      initrdUnits = config.system.build.systemdInitrdUnits;
      maskedUnits = cfg.maskedUnits;
      ignitionRoles = config.system.build.ignitionRolesBundle;
    };
  };
}
