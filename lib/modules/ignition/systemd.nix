##! lib/modules/ignition/systemd.nix — Ignition-flavoured systemd lib.
##!
##! Three pieces:
##!
##! - `ignitionInstallOptions`: the three install fields ignition adds
##!   on top of `commonInstallOptions` — `enabled` / `mask` / `dropins`.
##!   `wantedBy` / `requiredBy` / `upheldBy` / `aliases` come from the
##!   underlying stage-2 chain (`sharedOptions` includes them through
##!   `commonInstallOptions` after the §3.3 split) and get rendered
##!   into `[Install]` by the extended `commonUnitText`.
##!
##! - `ignition<Type>` per-unit-type submodule constructors. Each
##!   composes the stage-2 body options + `unitConfig` (which lifts
##!   `requires` / `wants` / `description` into `unitConfig`) + the
##!   bare `*Config` mixin from the systemd lib (which sets `name =
##!   "${name}.<ext>"` and per-type body bridges) + the ignition
##!   install overlay. The result is `attrsOf` (or `listOf` for
##!   mounts/automounts) submodule.
##!
##! - `toIgnitionUnit`: adapter that runs a body renderer
##!   (`serviceToUnit`, `timerToUnit`, …) and projects the renderer's
##!   `{ name; text; … }` into ignition's `{ name; contents; enabled;
##!   mask; dropins }`.
##!
##! Notes:
##!
##! - The composition reuses `serviceConfig` / `timerConfig` / etc.
##!   from the systemd lib (they only touch body fields, so
##!   install-model-agnostic). Stage 2's `stage2ServiceConfig` —
##!   which adds the coreutils/grep/sed default PATH — is NOT used
##!   here: ignition-shipped roles run their own services with
##!   absolute store paths in `ExecStart`, no implicit PATH default.
##!
##! - Inheriting `stage2<Type>Options` brings stage-2-only install
##!   fields (`enable`, `overrideStrategy`) along for the ride.
##!   `toIgnitionUnit` ignores them; they're cosmetic clutter on
##!   the schema but harmless.
##!
##! - `globalEnvironment` is not surfaced. Roles that want per-role
##!   env defaults can pre-merge inside the consumer module,
##!   mirroring `modules/systemd/system.nix:40-45`. YAGNI for v1.
##!
##! - This file does *not* build per-unit derivations the way
##!   `lib/modules/systemd/types.nix:80` does (`unit = makeUnit name
##!   config`). Ignition needs only the rendered text; no on-disk
##!   file derivation per unit.
{
  lib,
  pkgs,
}: let
  systemdLib = import ../systemd/lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../systemd/unit-options.nix {
    inherit lib systemdLib;
  };

  # Reused for `dropins.type` so we don't carry a parallel submodule
  # whose shape has to be kept in lock-step with the format's.
  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false; # irrelevant for dropinType
  };

  inherit
    (systemdLib)
    automountConfig
    mountConfig
    pathConfig
    serviceConfig
    sliceConfig
    socketConfig
    targetConfig
    timerConfig
    unitConfig
    ;

  inherit
    (systemdUnitOptions)
    stage2AutomountOptions
    stage2MountOptions
    stage2PathOptions
    stage2ServiceOptions
    stage2SliceOptions
    stage2SocketOptions
    stage2TimerOptions
    ;

  # Stage-2-style targets don't have a stage2TargetOptions wrapper
  # (target units have no body schema beyond commonUnitOptions); see
  # `lib/modules/systemd/types.nix:97-101`. Reuse stage2CommonUnitOptions
  # for parity.
  inherit (systemdUnitOptions) stage2CommonUnitOptions;

  # Ignition's three install fields — added on top of the stage-2
  # install fields (`wantedBy` etc.) which already live on the
  # underlying submodule via the §3.3 sharedOptions split. The
  # extended `commonUnitText` (§3.2) emits `[Install]` directives
  # for both stage 2 and ignition; ignition's `enabled`/`mask`/
  # `dropins` ride alongside in the JSON projection.
  ignitionInstallOptions = {
    enabled = lib.mkOption {
      type = lib.types.nullOr lib.types.bool;
      default = null;
      description = ''
        Whether ignition should record an enable/disable preset for
        the unit on first boot. Three states:

        * `null` (default) — leave the unit's preset state unchanged.
          Ignition writes neither an `enable` nor a `disable` line
          for this unit. Use this when shipping a unit whose
          enablement is managed elsewhere (or shouldn't be touched).
        * `true` — ignition writes `enable <name>` to
          `/etc/systemd/system-preset/20-ignition.preset`. The
          initrd's `aos-ignition-preset.service` then runs
          `systemctl --root=/sysroot preset-all`, which reads the
          preset file and the unit's `[Install]` section to create
          the runtime `.wants` / `.requires` / `.upholds` symlinks
          before switch_root.
        * `false` — ignition writes `disable <name>` to the same
          preset file, removing any matching symlinks when
          preset-all runs.

        This is a different concept from
        `systemd.services.<name>.enable` in NixOS, which gates
        whether the unit is rendered at all (rendering as a
        `/dev/null` symlink masks it when false).
      '';
    };
    mask = lib.mkOption {
      type = lib.types.nullOr lib.types.bool;
      default = null;
      description = ''
        Whether ignition should mask the unit by symlinking it to
        `/dev/null`, preventing systemd from ever starting it.
        Useful for silencing units shipped by `systemd.packages`
        that a role doesn't want active — e.g. masking
        `systemd-networkd-wait-online.service` on a role that
        doesn't need to block boot on network availability.

        `null` (default) leaves the unit's mask state unchanged.
        `true` masks. `false` actively unmasks (removes an existing
        `/dev/null` symlink if one is in place).
      '';
    };
    dropins = lib.mkOption {
      type = lib.types.listOf ignitionFormat.dropinType;
      default = [];
      description = ''
        Explicit list of drop-in fragments to ship alongside the
        unit. Each entry produces a `<unit-name>.d/<name>` file in
        `/etc/systemd/system/` after ignition applies the config.
        Drop-ins must be enumerated here explicitly because ignition
        cannot inspect the on-disk `/etc/systemd/system/` tree at
        config-build time.
      '';
    };
  };

  # Module fragment that adds the ignition install overlay to any
  # submodule. Used as the last element in each `submodule [...]`
  # composition below.
  ignitionInstallOverlay = {
    options = ignitionInstallOptions;
  };

  mkAttrsType = modules:
    lib.types.attrsOf (lib.types.submodule modules);

  mkListType = modules:
    lib.types.listOf (lib.types.submodule modules);

  # Project a renderer's `{ name; text; ... }` output plus the
  # ignition-specific install fields into ignition's
  # `{ name; contents; enabled; mask; dropins }` shape.
  toIgnitionUnit = renderer: def: let
    rendered = renderer def;
  in {
    inherit (rendered) name;
    contents = rendered.text;
    inherit (def) enabled mask dropins;
  };
in {
  inherit ignitionInstallOptions toIgnitionUnit;

  ignitionServices = mkAttrsType [
    stage2ServiceOptions
    unitConfig
    serviceConfig
    ignitionInstallOverlay
  ];

  ignitionTargets = mkAttrsType [
    stage2CommonUnitOptions
    unitConfig
    targetConfig
    ignitionInstallOverlay
  ];

  ignitionSockets = mkAttrsType [
    stage2SocketOptions
    unitConfig
    socketConfig
    ignitionInstallOverlay
  ];

  ignitionTimers = mkAttrsType [
    stage2TimerOptions
    unitConfig
    timerConfig
    ignitionInstallOverlay
  ];

  ignitionPaths = mkAttrsType [
    stage2PathOptions
    unitConfig
    pathConfig
    ignitionInstallOverlay
  ];

  ignitionSlices = mkAttrsType [
    stage2SliceOptions
    unitConfig
    sliceConfig
    ignitionInstallOverlay
  ];

  ignitionMounts = mkListType [
    stage2MountOptions
    unitConfig
    mountConfig
    ignitionInstallOverlay
  ];

  ignitionAutomounts = mkListType [
    stage2AutomountOptions
    unitConfig
    automountConfig
    ignitionInstallOverlay
  ];
}
