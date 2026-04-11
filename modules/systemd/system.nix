##! modules/systemd/system.nix — Stage 2 systemd module (parallel / stage 3)
##!
##! Declares the typed systemd.* option tree (services, timers, sockets, …),
##! wires `systemd.units` via the *-ToUnit rendering functions, and produces
##! `system.build.systemdNewSystemUnits` — a derivation whose output is a
##! directory matching /etc/systemd/system.
##!
##! Stage 3 only. For this stage the options and the derivation live under
##! a *New*-suffixed namespace (`systemdNew.*` and
##! `system.build.systemdNewSystemUnits`) so that the existing untyped
##! `systemd.services` / `systemd.timers` options in modules/base/build.nix
##! and the old `renderUnit` / `renderTimer` pipeline can coexist with the
##! new typed pipeline. Stage 4 atomically:
##!   * renames `systemdNew` to `systemd` here,
##!   * deletes the old option declarations and renderers from build.nix,
##!   * replaces `${unitScripts}` / `${timerScripts}` in the toplevel build
##!     with a single `ln -s ${config.system.build.systemdSystemUnits}
##!     $out/etc/systemd/system` line.
##!
##! Nothing consumes `systemdNew.*` yet (no module has been migrated over),
##! so the generated `systemdNewSystemUnits` derivation is effectively empty
##! — just the `systemd.packages`-contributed units, if any. The point of
##! stage 3 is to prove the wiring eval-types, parses, and builds.
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

  cfg = config.systemdNew;

  # --- globalEnvironment pre-merge (spec §4.2) --------------------------
  #
  # Upstream nixpkgs bakes `cfg.globalEnvironment // def.environment` into
  # `serviceToUnit`, reading `cfg` through a closure over the whole NixOS
  # config. The AOS port moves that merge out here so the library in
  # `_lib.nix` stays a pure function of its inputs, reusable for initrd
  # / nspawn / user units without re-parameterisation. Per-service
  # values still win over globals because `//` is right-biased and
  # `svc.environment` is on the right.
  mergeGlobalEnv = svc:
    svc
    // {
      environment = cfg.globalEnvironment // svc.environment;
    };
  servicesWithGlobalEnv = lib.mapAttrs (_: mergeGlobalEnv) cfg.services;

  # --- union of *-ToUnit outputs -----------------------------------------
  #
  # Mirrors nixos/modules/system/boot/systemd.nix:702-713: run each
  # category through its renderer, key the result by the rendered unit
  # name (`chronyd.service`, not `chronyd`), and union the lot. Modules
  # that write directly into `systemd.units.<name>` with raw text still
  # work — mkMerge handles the union because `systemd.units` is declared
  # below as `attrsOf (submodule [...])`, whose merge runs across all
  # contributors.
  withName = cfgToUnit: c: lib.nameValuePair c.name (cfgToUnit c);
  renderedUnits =
    lib.mapAttrs' (_: withName systemdLib.serviceToUnit) servicesWithGlobalEnv
    // lib.mapAttrs' (_: withName systemdLib.targetToUnit) cfg.targets
    // lib.mapAttrs' (_: withName systemdLib.socketToUnit) cfg.sockets
    // lib.mapAttrs' (_: withName systemdLib.timerToUnit) cfg.timers
    // lib.mapAttrs' (_: withName systemdLib.pathToUnit) cfg.paths
    // lib.mapAttrs' (_: withName systemdLib.sliceToUnit) cfg.slices
    // lib.listToAttrs (builtins.map (withName systemdLib.mountToUnit) cfg.mounts)
    // lib.listToAttrs (builtins.map (withName systemdLib.automountToUnit) cfg.automounts);
in {
  options.systemdNew = {
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.systemd;
      description = ''
        The systemd package whose default unit files live in
        `$package/lib/systemd/system/` and are found by systemd natively at
        runtime. AOS does not move these into `$package/example/systemd/`
        the way nixpkgs does; the defaults stay discoverable through
        the `SYSTEM_DATA_UNIT_DIR` patch in `pkgs/system/systemd.nix`.
      '';
    };

    packages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = ''
        AOS packages that ship systemd unit files under
        `$pkg/lib/systemd/system/` (or `$pkg/etc/systemd/system/`).
        Their unit files are symlinked into `/etc/systemd/system/` at
        image build time by `generateUnits`. This is how a module
        registers an upstream-provided unit without re-declaring it
        via `systemdNew.services.<name>`.
      '';
    };

    globalEnvironment = lib.mkOption {
      type = with lib.types; attrsOf (nullOr (oneOf [str path package]));
      default = {};
      description = ''
        Environment variables merged into every
        `systemdNew.services.<name>.environment`. Matches nixpkgs
        semantics: per-service values win over globals. Applied as a
        pre-merge step in this module (see the module source), rather
        than inside `_lib.nix`, so the library stays a pure function
        of its inputs.
      '';
    };

    services = lib.mkOption {
      type = systemdTypes.services;
      default = {};
      description = "Typed systemd .service units.";
    };

    targets = lib.mkOption {
      type = systemdTypes.targets;
      default = {};
      description = "Typed systemd .target units.";
    };

    sockets = lib.mkOption {
      type = systemdTypes.sockets;
      default = {};
      description = "Typed systemd .socket units.";
    };

    timers = lib.mkOption {
      type = systemdTypes.timers;
      default = {};
      description = "Typed systemd .timer units.";
    };

    paths = lib.mkOption {
      type = systemdTypes.paths;
      default = {};
      description = "Typed systemd .path units.";
    };

    slices = lib.mkOption {
      type = systemdTypes.slices;
      default = {};
      description = "Typed systemd .slice units.";
    };

    mounts = lib.mkOption {
      type = systemdTypes.mounts;
      default = [];
      description = "Typed systemd .mount units. Keyed by `where`, not by name.";
    };

    automounts = lib.mkOption {
      type = systemdTypes.automounts;
      default = [];
      description = "Typed systemd .automount units. Keyed by `where`, not by name.";
    };

    units = lib.mkOption {
      type = systemdTypes.units;
      default = {};
      description = ''
        Generic escape-hatch unit type. Modules that want to ship raw
        unit text — e.g. to extend an upstream systemd.packages-provided
        unit via `overrideStrategy = "asDropin"` — can declare entries
        here directly. The `systemdNew.services` / `systemdNew.targets`
        / etc. renderers feed into this attrset automatically in
        `config.systemdNew.units` below.
      '';
    };
  };

  config = {
    # Merge the rendered unit attrsets back into `systemdNew.units` so
    # `generateUnits` can see everything (both raw unit text from
    # modules that bypassed the typed options and compiled text from
    # the *-ToUnit renderers) in a single place.
    systemdNew.units = renderedUnits;

    # Expose the /etc/systemd/system directory as a single derivation.
    # Stage 4 will wire this into `$out/etc/systemd/system` via one
    # `ln -s` line in `modules/base/build.nix`'s toplevel script. For
    # stage 3 the derivation just sits alongside the old `${unitScripts}`
    # / `${timerScripts}` pipeline without being consumed.
    system.build.systemdNewSystemUnits = systemdLib.generateUnits {
      type = "system";
      units = config.systemdNew.units;
      # AOS stage-2: systemd finds upstream units at
      # /lib/systemd/system/ natively (see spec §5.5 + the
      # `0001-remove-usr-lib-unit-lookup-paths.patch` in
      # `pkgs/system/systemd.nix`). Empty lists are fine here.
      upstreamUnits = [];
      upstreamWants = [];
      packages = config.systemdNew.packages;
      package = config.systemdNew.package;
    };
  };
}
