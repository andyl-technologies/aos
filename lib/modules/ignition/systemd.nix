##! lib/modules/ignition/systemd.nix — typed role systemd inputs.
##!
##! `ignition<Type>` per-unit-type submodule constructors used by
##! `modules/roles/default.nix` for `aos.roles.<name>.systemd.*`. Each
##! composes the stage-2 body options + `unitConfig` (which lifts
##! `requires` / `wants` / `description` into `unitConfig`) + the
##! bare `*Config` mixin from the systemd lib (which sets `name =
##! "${name}.<ext>"` and per-type body bridges).
##!
##! Notes:
##!
##! - The composition reuses `serviceConfig` / `timerConfig` / etc.
##!   from the systemd lib (they only touch body fields, so
##!   install-model-agnostic). Stage 2's `stage2ServiceConfig` —
##!   which adds the coreutils/grep/sed default PATH — is NOT used
##!   here: role-shipped services run with absolute store paths in
##!   `ExecStart`, no implicit PATH default.
##!
##! - The three ignition-native install fields (`enabled`, `mask`,
##!   `dropins`) and the `toIgnitionUnit` projection were removed in
##!   spec v12 §5.6.4: under the composefs `/etc` model the role's
##!   `[Install]` symlinks ride in the EROFS image (via the dump
##!   recursion) and in the per-gen ignition lower (via the
##!   `render-role.nix` helper's predicted `storage.links`), and
##!   `aos-ignition-preset.service` is gone (spec v12 §6.1.6). The
##!   typed `wantedBy` / `overrideStrategy` surface (inherited
##!   through `stage2<Type>Options`) is what the helper consumes.
##!
##! - `globalEnvironment` is not surfaced. Roles that want per-role
##!   env defaults can pre-merge inside the consumer module,
##!   mirroring `modules/systemd/system.nix:40-45`. YAGNI for v1.
{
  lib,
  pkgs,
}: let
  systemdLib = import ../systemd/lib.nix {inherit lib pkgs;};
  systemdUnitOptions = import ../systemd/unit-options.nix {
    inherit lib systemdLib;
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

  mkAttrsType = modules:
    lib.types.attrsOf (lib.types.submodule modules);

  mkListType = modules:
    lib.types.listOf (lib.types.submodule modules);
in {
  ignitionServices = mkAttrsType [
    stage2ServiceOptions
    unitConfig
    serviceConfig
  ];

  ignitionTargets = mkAttrsType [
    stage2CommonUnitOptions
    unitConfig
    targetConfig
  ];

  ignitionSockets = mkAttrsType [
    stage2SocketOptions
    unitConfig
    socketConfig
  ];

  ignitionTimers = mkAttrsType [
    stage2TimerOptions
    unitConfig
    timerConfig
  ];

  ignitionPaths = mkAttrsType [
    stage2PathOptions
    unitConfig
    pathConfig
  ];

  ignitionSlices = mkAttrsType [
    stage2SliceOptions
    unitConfig
    sliceConfig
  ];

  ignitionMounts = mkListType [
    stage2MountOptions
    unitConfig
    mountConfig
  ];

  ignitionAutomounts = mkListType [
    stage2AutomountOptions
    unitConfig
    automountConfig
  ];
}
