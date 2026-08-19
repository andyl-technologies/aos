##! modules/systemd/system.nix — Stage 2 systemd module
##!
##! Declares the typed `systemd.*` option tree (services, timers, sockets,
##! targets, paths, slices, mounts, automounts, units, plus the package /
##! packages / globalEnvironment plumbing), wires `systemd.units` via the
##! *-ToUnit rendering functions in `lib/modules/systemd/lib.nix`, and produces
##! `system.build.systemdSystemUnits` — a derivation whose output is a
##! directory matching `/etc/systemd/system/`.
##!
##! `generateUnits` returns a pure unit-data map. `modules/base/build.nix`
##! folds its flattened `/etc` entries into `system.build.configManifest`, and
##! the thin `materializeUnits` adapter reconstructs the builder-side unit
##! directory from that manifest for `system.build.toplevel`.
{
  config,
  lib,
  pkgs,
  provenance,
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
        via `systemd.services.<name>`. Package recipes expose the relative
        leaves through `passthru.systemdUnitInventory.<type>`; this inventory
        is frozen into the image base library so on-host evaluation never
        enumerates a derivation output.
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

  # Pure render/assemble split: the unit-body data that the
  # `systemdSystemUnits` derivation is the imperative materialization of.
  # `generateUnits` is intentionally left untouched (so the built unit
  # directory stays byte-for-byte identical except the documented F2-A
  # job-script ExecStart change); this value surfaces the same rendered
  # bodies as host-portable data for `system.build.configManifest`. The
  # `text` here is the *manifest* form: job-script store paths are replaced
  # by `#aos-jobscript:<key>#` placeholders. (replaceStrings does not strip
  # string-context, so the value still carries the job-script drvs in context;
  # toJSON drops context and nothing forces this, so the manifest serializes
  # with no derivation — the placeholder swap is for the host-portable text,
  # not a context guarantee.)
  options.system.build.systemdUnitBodies = lib.mkOption {
    # Free-form `attrs` values (not a submodule) so the rendered data stays
    # plain JSON with no injected `_module` key. Each value is
    # `{ text; enable; aliases; wantedBy; requiredBy; upheldBy; }` where
    # `text` is the manifest-form unit body (or null when masked).
    type = lib.types.attrsOf lib.types.attrs;
    internal = true;
    default = {};
    description = ''
      Pure render of every systemd unit body keyed by full unit name, the
      data contract behind `system.build.systemdSystemUnits`.
    '';
  };

  options.system.build.systemdEtcEntries = lib.mkOption {
    type = lib.types.attrsOf lib.types.attrs;
    internal = true;
    default = {};
    description = ''
      Pure manifest entries below `/etc/systemd/system`, flattened from
      `systemdUnitBodies` by the shared systemd layout renderer.
    '';
  };

  options.system.build.systemdMaterializationData = lib.mkOption {
    type = lib.types.attrs;
    internal = true;
    default = {
      etc = config.system.build.systemdEtcEntries;
      jobScripts = config.system.build.systemdJobScripts;
    };
    description = ''
      Manifest-shaped `{ etc; jobScripts; }` data consumed by the builder-side
      unit materializer. The base build module binds this to configManifest;
      the default keeps the standalone systemd module testable.
    '';
  };

  # Every job script's text, keyed `"<unit>:<slot>.<index>"`,
  # folded across all services. Consumed by `system.build.configManifest`
  # (`manifest.jobScripts`); the materializer writes each `text` to a
  # generation-local `aos-job-scripts/<key>` path and rewrites the matching
  # `#aos-jobscript:<key>#` placeholder in the unit body to point there.
  options.system.build.systemdJobScripts = lib.mkOption {
    # Free-form `attrs` values (not a submodule) to avoid an injected
    # `_module` key in the manifest JSON. Each value is
    # `{ text; mode; name; }` (verbatim body incl. shebang, octal mode,
    # sanitized short name for logs).
    type = lib.types.attrsOf lib.types.attrs;
    internal = true;
    default = {};
    description = "Job-script texts keyed by `<unit>:<slot>.<index>`.";
  };

  options.system.build.systemdUnitOwners = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    internal = true;
    readOnly = true;
    description = "Resolver-authenticated owner of each rendered systemd unit.";
  };

  options.system.build.systemdUnitActions = lib.mkOption {
    type = lib.types.attrsOf lib.types.attrs;
    internal = true;
    readOnly = true;
    description = "Pure per-unit reconcile records for the config manifest.";
  };

  config = let
    # --- X-* contract eval-time guards (spec §7.3) ---------------------
    #
    # The activation reconciler honours the X-* knobs added
    # in this refactor; these assertions catch degenerate combinations at
    # eval time so a misconfigured unit fails the build rather than
    # silently doing nothing (or the wrong thing) on a live upgrade.
    # A service can reload in place iff it declares ExecReload= — either
    # directly in serviceConfig, or via the `reload` option (which sets
    # serviceConfig.ExecReload through a mkDefault in serviceOptions).
    hasExecReload = svc: (svc.serviceConfig ? ExecReload) || ((svc.reload or "") != "");

    pureSystemUnits = systemdLib.generateUnits {
      type = "system";
      units = config.systemd.units;
      upstreamUnits = [];
      upstreamWants = [];
      packages = config.systemd.packages;
      package = config.systemd.package;
      packageOwners = builtins.listToAttrs (builtins.map (package:
        lib.nameValuePair
        (builtins.unsafeDiscardStringContext (builtins.toString package))
        (provenance.ownerOfListAttr
          ["systemd" "packages"]
          "outPath"
          package.outPath))
      config.systemd.packages);
    };

    artifactOwner = path: name: let
      owners = provenance.dependencyOwnersOfAttr path name;
    in
      if builtins.length owners == 1
      then builtins.head owners
      else if owners == []
      then "@base"
      else throw "systemd artifact ${name} depends on multiple owners: ${lib.concatStringsSep ", " owners}";
    ownedAttrUnits = path: units:
      lib.mapAttrs' (name: unit:
        lib.nameValuePair unit.name (artifactOwner path name))
      units;
    ownedListUnits = path: units: let
      records = builtins.map (unit:
        lib.nameValuePair unit.name
        (provenance.ownerOfListAttr path "where" unit.where))
      units;
      names = builtins.map (record: record.name) records;
      duplicates =
        builtins.filter
        (name: builtins.length (builtins.filter (candidate: candidate == name) names) > 1)
        (lib.unique names);
    in
      if duplicates == []
      then builtins.listToAttrs records
      else throw "list-backed systemd definitions collide at final unit name(s): ${lib.concatStringsSep ", " duplicates}";
    typedOwnerSets = [
      (ownedAttrUnits ["systemd" "services"] cfg.services)
      (ownedAttrUnits ["systemd" "targets"] cfg.targets)
      (ownedAttrUnits ["systemd" "sockets"] cfg.sockets)
      (ownedAttrUnits ["systemd" "timers"] cfg.timers)
      (ownedAttrUnits ["systemd" "paths"] cfg.paths)
      (ownedAttrUnits ["systemd" "slices"] cfg.slices)
      (ownedListUnits ["systemd" "mounts"] cfg.mounts)
      (ownedListUnits ["systemd" "automounts"] cfg.automounts)
    ];
    typedNames = lib.concatLists (builtins.map builtins.attrNames typedOwnerSets);
    duplicateTypedNames =
      builtins.filter
      (name: builtins.length (builtins.filter (candidate: candidate == name) typedNames) > 1)
      (lib.unique typedNames);
    typedUnitOwners =
      if duplicateTypedNames != []
      then throw "typed systemd definitions collide at final unit name(s): ${lib.concatStringsSep ", " duplicateTypedNames}"
      else builtins.foldl' (acc: owners: acc // owners) {} typedOwnerSets;
    rawUnitNames =
      builtins.attrNames
      (builtins.removeAttrs cfg.units (builtins.attrNames typedUnitOwners));
    rawUnitOwners = builtins.listToAttrs (builtins.map (name:
      lib.nameValuePair name
      (provenance.ownerOfAttr ["systemd" "units"] name))
    rawUnitNames);
    typedRawCollisionCheck =
      builtins.foldl' (checked: name: let
        allDefs = provenance.definitionsOfAttr ["systemd" "units"] name;
        # `config.systemd.units = renderedUnits` contributes exactly one
        # synthetic @base definition for every typed unit. Remove exactly one
        # such record; every remaining definition is a genuine raw-unit source,
        # including a second @base definition from another image module.
        stripped =
          builtins.foldl' (state: definition:
            if !state.removed && definition.owner == "@base"
            then state // {removed = true;}
            else state // {definitions = state.definitions ++ [definition];}) {
            removed = false;
            definitions = [];
          }
          allDefs;
        rawDefs = stripped.definitions;
        rawOwners = lib.unique (builtins.map (definition: definition.owner) rawDefs);
        typedOwner = typedUnitOwners.${name};
      in
        if rawDefs == []
        then checked
        else throw "raw systemd unit ${name} collides with typed owner ${typedOwner}; raw owner(s): ${lib.concatStringsSep ", " rawOwners}")
      true
      (builtins.attrNames typedUnitOwners);
    unitOwners = builtins.seq typedRawCollisionCheck (typedUnitOwners // rawUnitOwners);

    asList = value:
      if value == null
      then []
      else if builtins.isList value
      then value
      else [value];
    credentialHandles = svc:
      lib.unique (builtins.map
        (entry: builtins.head (lib.splitString ":" (builtins.toString entry)))
        (asList (svc.serviceConfig.LoadCredential or [])
          ++ asList (svc.serviceConfig.LoadCredentialEncrypted or [])));
    reconcileAction = kind: unit:
      if kind == "target" || !unit.restartIfChanged
      then "none"
      else if unit.reloadIfChanged
      then "reload"
      else "restart";
    attrActions = kind: units:
      lib.mapAttrs' (_: unit:
        lib.nameValuePair unit.name {
          action = reconcileAction kind unit;
          credentials =
            if kind == "service"
            then credentialHandles unit
            else [];
          enable = unit.enable;
        })
      units;
    listActions = kind: units:
      builtins.listToAttrs (builtins.map (unit:
        lib.nameValuePair unit.name {
          action = reconcileAction kind unit;
          credentials = [];
          enable = unit.enable;
        })
      units);
    typedUnitActions =
      attrActions "service" cfg.services
      // attrActions "target" cfg.targets
      // attrActions "socket" cfg.sockets
      // attrActions "timer" cfg.timers
      // attrActions "path" cfg.paths
      // attrActions "slice" cfg.slices
      // listActions "mount" cfg.mounts
      // listActions "automount" cfg.automounts;
    rawUnitActions = builtins.listToAttrs (builtins.map (name:
      lib.nameValuePair name {
        action = "restart";
        credentials = [];
        enable = cfg.units.${name}.enable;
      })
    rawUnitNames);

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
    assertions =
      stopOnReconfAttrAsserts
      ++ stopOnReconfListAsserts
      ++ targetReloadTriggerAsserts;

    warnings = reloadWithoutExecReloadWarnings;

    # Merge the rendered unit attrsets back into `systemd.units` so
    # `generateUnits` can see everything (both raw unit text from
    # modules that bypassed the typed options and compiled text from
    # the *-ToUnit renderers) in a single place.
    systemd.units = renderedUnits;

    # Materialize the builder-side directory from the same manifest emitted by
    # the on-host evaluator. No independently assembled systemd derivation path
    # remains: byte layout and job-script substitution are driven by
    # `configManifest.etc` and `configManifest.jobScripts`.
    system.build.systemdSystemUnits = systemdLib.materializeUnits {
      type = "system";
      inherit (config.system.build.systemdMaterializationData) etc jobScripts;
    };

    # --- Pure render values ---------------------------------------------
    #
    # Fold every service's F2-A job-script records into the flat
    # `systemdJobScripts` map, and build the manifest-form unit bodies by
    # rewriting each build-side job-script store path to its placeholder.
    # The build-side `generateUnits` derivation is untouched, so this is
    # purely additive data — it does not affect `systemdSystemUnits`.
    system.build.systemdJobScripts = let
      allJobScripts =
        lib.concatLists (lib.mapAttrsToList (_: svc: svc.jobScripts) config.systemd.services);
    in
      lib.listToAttrs (builtins.map (j:
        lib.nameValuePair j.key {
          text = j.body;
          inherit (j) mode;
          name = j.scriptName;
        })
      allJobScripts);

    # The renderer returns no derivations. Job scripts appear only as keys and
    # placeholders here; their text lives in `systemdJobScripts`.
    system.build.systemdUnitBodies = pureSystemUnits;
    system.build.systemdEtcEntries = systemdLib.unitsToEtc pureSystemUnits;
    system.build.systemdUnitOwners = unitOwners;
    system.build.systemdUnitActions = typedUnitActions // rawUnitActions;

    # Route the rendered unit directory through environment.etc so
    # the EROFS image carries it as a real directory of symlinks (the
    # composefs dump script's `mode == "symlink"` + `os.path.isdir(source)`
    # branch recurses — spec v12 §5.2). At runtime, this directory
    # merges with the per-generation config lower's `/etc/systemd/system/`
    # without one side shadowing the other.
    environment.etc."systemd/system" = {
      source = config.system.build.systemdSystemUnits;
    };
  };
}
