##! modules/systemd/system.nix — Stage 2 systemd module
##!
##! Declares the typed `systemd.*` option tree (services, timers, sockets,
##! targets, paths, slices, mounts, automounts, units, plus the package /
##! packages / globalEnvironment plumbing), wires `systemd.units` via the
##! *-ToUnit rendering functions in `lib/modules/systemd/lib.nix`, and produces
##! `system.build.systemdSystemUnits` — a derivation whose output is a
##! directory matching `/etc/systemd/system/`.
##!
##! `modules/base/build.nix` pulls the produced directory into the
##! toplevel with one `ln -s ${config.system.build.systemdSystemUnits}
##! $out/etc/systemd/system` line. The previous untyped `renderUnit` /
##! `renderTimer` heredoc pipeline has been deleted as part of spec v3.1
##! stage 4.
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

  cfg = config.systemd;

  # --- globalEnvironment pre-merge (spec §4.2) --------------------------
  #
  # Upstream nixpkgs bakes `cfg.globalEnvironment // def.environment` into
  # `serviceToUnit`, reading `cfg` through a closure over the whole NixOS
  # config. The AOS port moves that merge out here so the library in
  # `lib/modules/systemd/lib.nix` stays a pure function of its inputs, reusable for initrd
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
  options.systemd = {
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
        via `systemd.services.<name>`.
      '';
    };

    globalEnvironment = lib.mkOption {
      type = with lib.types; attrsOf (nullOr (oneOf [str path package]));
      default = {};
      description = ''
        Environment variables merged into every
        `systemd.services.<name>.environment`. Matches nixpkgs
        semantics: per-service values win over globals. Applied as a
        pre-merge step in this module (see the module source), rather
        than inside `lib/modules/systemd/lib.nix`, so the library stays a pure function
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
        here directly. The `systemd.services` / `systemd.targets`
        / etc. renderers feed into this attrset automatically in
        `config.systemd.units` below.
      '';
    };
  };

  # Declare `system.build.systemdSystemUnits` as a real option so
  # `modules/base/build.nix` can read it via `config.system.build.
  # systemdSystemUnits`. It's defined below in `config` and consumed
  # by build.nix's toplevel script via a single `ln -s` line.
  options.system.build.systemdSystemUnits = lib.mkOption {
    type = lib.types.package;
    description = ''
      Derivation whose output is an assembled `/etc/systemd/system/`
      directory produced by `generateUnits`. Staged into the toplevel
      by `modules/base/build.nix`.
    '';
  };

  config = let
    # --- X-* contract eval-time guards (spec §7.3) ---------------------
    #
    # The `apm activate-reconcile` reconciler honours the X-* knobs added
    # in this refactor; these assertions catch degenerate combinations at
    # eval time so a misconfigured unit fails the build rather than
    # silently doing nothing (or the wrong thing) on a live upgrade.
    # A service can reload in place iff it declares ExecReload= — either
    # directly in serviceConfig, or via the `reload` option (which sets
    # serviceConfig.ExecReload through a mkDefault in serviceOptions).
    hasExecReload = svc: (svc.serviceConfig ? ExecReload) || ((svc.reload or "") != "");

    # `stopOnReconfiguration` is target-only (NixOS semantics). Flag it on
    # any non-target typed unit. attrset-keyed categories:
    nonTargetAttrCats = {
      services = cfg.services;
      sockets = cfg.sockets;
      timers = cfg.timers;
      paths = cfg.paths;
      slices = cfg.slices;
    };
    # list-keyed categories (mounts/automounts are listOf, keyed by where):
    nonTargetListCats = {
      mounts = cfg.mounts;
      automounts = cfg.automounts;
    };
    stopOnReconfAttrAsserts = lib.concatLists (
      lib.mapAttrsToList (
        cat: units:
          lib.mapAttrsToList (n: u: {
            assertion = !u.stopOnReconfiguration;
            message = "systemd.${cat}.${n}: stopOnReconfiguration only applies to .target units.";
          })
          units
      )
      nonTargetAttrCats
    );
    stopOnReconfListAsserts = lib.concatLists (
      lib.mapAttrsToList (
        cat: units:
          lib.map (u: {
            assertion = !u.stopOnReconfiguration;
            message = "systemd.${cat} entry `${u.name}': stopOnReconfiguration only applies to .target units.";
          })
          units
      )
      nonTargetListCats
    );

    # `reloadTriggers` on a .target can never take effect: a target is
    # never reloaded, and the reconciler never restarts targets directly
    # (its per-type policy). Move the trigger to a service.
    targetReloadTriggerAsserts =
      lib.mapAttrsToList (n: t: {
        assertion = t.reloadTriggers == [];
        message = "systemd.targets.${n}: reloadTriggers has no effect on a .target (targets are neither reloaded nor restarted directly); move the trigger to a service.";
      })
      cfg.targets;

    # `onlyManualStart` on a .scope unit would be an error too (spec §7.3),
    # but AOS has no `scope` unit type (none in lib/modules/systemd/
    # types.nix), so there is no eval-time data source to check; revisit if
    # a scopes option is ever added.

    # `reloadIfChanged = true` without an ExecReload= falls back to restart
    # at reconcile time — usually not what the author intended. Warn.
    reloadWithoutExecReloadWarnings = lib.concatLists (
      lib.mapAttrsToList (
        n: svc:
          lib.optional (svc.reloadIfChanged && !hasExecReload svc)
          "systemd.services.${n}: reloadIfChanged = true but the unit has no ExecReload= (set serviceConfig.ExecReload or the `reload` option); it will fall back to restart during a live upgrade."
      )
      cfg.services
    );
  in {
    # v1 doesn't model package-provided units (no IFD; we can't
    # enumerate `$pkg/lib/systemd/system/` at eval time, which the
    # `render-role.nix` drift assertion and `etc-merge-safety` check
    # both depend on). Track as future work — spec v12 §10 item #2.
    assertions =
      [
        {
          assertion = config.systemd.packages == [];
          message = ''
            systemd.packages is not yet supported with the composefs
            /etc model (spec v12 §10 future-work #2). Re-introducing
            package-provided units requires either accepting that the
            merge-safety diff data source becomes incomplete or
            generating the unit list at build time via a derivation.
          '';
        }
      ]
      ++ stopOnReconfAttrAsserts
      ++ stopOnReconfListAsserts
      ++ targetReloadTriggerAsserts;

    warnings = reloadWithoutExecReloadWarnings;

    # Merge the rendered unit attrsets back into `systemd.units` so
    # `generateUnits` can see everything (both raw unit text from
    # modules that bypassed the typed options and compiled text from
    # the *-ToUnit renderers) in a single place.
    systemd.units = renderedUnits;

    # Expose the /etc/systemd/system directory as a single derivation.
    # Routed into the EROFS metadata image via `environment.etc`
    # below; the composefs dump script (spec v12 §5.2) recurses into
    # the directory so it lands as a real directory of symlinks
    # rather than a single symlink (which would be shadowed by the
    # ignition role lower at runtime).
    system.build.systemdSystemUnits = systemdLib.generateUnits {
      type = "system";
      units = config.systemd.units;
      # AOS stage-2: systemd finds upstream units at
      # /lib/systemd/system/ natively (see spec §5.5 + the
      # `0001-remove-usr-lib-unit-lookup-paths.patch` in
      # `pkgs/system/systemd.nix`). Empty lists are fine here.
      upstreamUnits = [];
      upstreamWants = [];
      packages = config.systemd.packages;
      package = config.systemd.package;
    };

    # Route the rendered unit directory through environment.etc so
    # the EROFS image carries it as a real directory of symlinks (the
    # composefs dump script's `mode == "symlink"` + `os.path.isdir(source)`
    # branch recurses — spec v12 §5.2). At runtime, this directory
    # merges with the ignition role lower's `/etc/systemd/system/`
    # without one side shadowing the other.
    environment.etc."systemd/system" = {
      source = config.system.build.systemdSystemUnits;
    };
  };
}
