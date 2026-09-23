##! pkgs/system/_systemd-abilities/platform/system.nix — Stage 2 systemd module
##!
##! Declares the typed `systemd.*` option tree (services, timers, sockets,
##! targets, paths, slices, mounts, automounts, and global environment),
##! derives the internal `systemd.units` rendering through the
##! *-ToUnit rendering functions in `pkgs/system/_systemd-abilities/platform/render.nix`, and produces
##! `system.build.systemdSystemUnits` — a derivation whose output is a
##! directory matching `/etc/systemd/system/`.
##!
##! `generateUnits` returns a pure unit-data map. `modules/base/build.nix`
##! folds its flattened `/etc` entries into `system.build.configManifest`, and
##! the thin `materializeUnits` adapter reconstructs the builder-side unit
##! directory from that manifest for `system.build.toplevel`.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  provenance,
  ...
}: let
  managerBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "system-manager";
  selected = builtins.length managerBindings == 1;
  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  rendererPackages = {
    bash = packageArtifactFor (packageOutput "bash");
    coreutils = packageArtifactFor (packageOutput "coreutils");
    findutils = packageArtifactFor (packageOutput "findutils");
    grep = packageArtifactFor (packageOutput "grep");
    sed = packageArtifactFor (packageOutput "sed");
    systemd = packageArtifactFor (lib.abilities.packageOutput {});
  };
  systemdLib = import ./render.nix {
    inherit lib;
    pkgs = rendererPackages;
  };
  systemdUnitOptions = import ./unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ./types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };

  cfg = config.systemd;
  providerRenderSelectorType = lib.types.submodule {
    config._module.strict = true;
    options = {
      package = lib.mkOption {type = lib.types.nonEmptyStr;};
      output = lib.mkOption {type = lib.types.nonEmptyStr;};
      path = lib.mkOption {type = lib.types.nonEmptyStr;};
    };
  };
  providerRenderPlanType = lib.types.submodule {
    config._module.strict = true;
    options = {
      input = lib.mkOption {
        type = lib.types.str;
        description = "Canonical JSON input for the authenticated systemd renderer.";
      };
      name = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Stable diagnostic name for the rendered artifact.";
      };
      selectors = lib.mkOption {
        type = lib.types.listOf providerRenderSelectorType;
        default = [];
        description = "Authenticated package output paths used by symbolic render input.";
      };
    };
  };

  # --- globalEnvironment pre-merge (spec §4.2) --------------------------
  #
  # Upstream nixpkgs bakes `cfg.globalEnvironment // def.environment` into
  # `serviceToUnit`, reading `cfg` through a closure over the whole NixOS
  # config. The AOS port moves that merge out here so the library in
  # `pkgs/system/_systemd-abilities/platform/render.nix` stays a pure function of its inputs, reusable for initrd
  # / nspawn / user units without re-parameterisation. Per-service
  # values still win over globals because `//` is right-biased and
  # `svc.environment` is on the right.
  mergeGlobalEnv = svc:
    svc
    // {
      environment = cfg.globalEnvironment // svc.environment;
    };
  servicesWithGlobalEnv = lib.mapAttrs (_: mergeGlobalEnv) cfg.services;

  # Run each typed category through its renderer, key the result by the
  # rendered unit name (`chronyd.service`, not `chronyd`), and join the result
  # into the manager's internal unit projection.
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
    providerUnitPlans = lib.mkOption {
      type = lib.types.listOf providerRenderPlanType;
      default = [];
      internal = true;
      extensible = true;
      description = ''
        Pure render plans produced by authenticated provider modules. The
        selected manager materializes and collision-checks them once.
      '';
    };

    providerManagerConfigurationPlans = lib.mkOption {
      type = lib.types.listOf providerRenderPlanType;
      default = [];
      internal = true;
      extensible = true;
      description = "Pure manager-configuration plans from authenticated systemd providers.";
    };

    providerNetworkConfigurationPlans = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        config._module.strict = true;
        options = {
          input = lib.mkOption {type = lib.types.str;};
          name = lib.mkOption {type = lib.types.nonEmptyStr;};
          selectors = lib.mkOption {
            type = lib.types.listOf providerRenderSelectorType;
            default = [];
          };
          resolverEnabled = lib.mkOption {
            type = lib.types.bool;
            description = "Whether the plan owns authoritative resolver configuration.";
          };
        };
      });
      default = [];
      internal = true;
      extensible = true;
      description = "Pure network-configuration plans from the authenticated systemd controller.";
    };

    globalEnvironment = lib.mkOption {
      type = with lib.types; attrsOf (nullOr (oneOf [str path package]));
      default = {};
      description = ''
        Environment variables merged into every
        `systemd.services.<name>.environment`. Matches nixpkgs
        semantics: per-service values win over globals. Applied as a
        pre-merge step in this module (see the module source), rather
        than inside `pkgs/system/_systemd-abilities/platform/render.nix`, so the library stays a pure function
        of its inputs.
      '';
    };

    services = lib.mkOption {
      type = systemdTypes.services;
      default = {};
      extensible = true;
      description = "Typed systemd .service units.";
    };

    targets = lib.mkOption {
      type = systemdTypes.targets;
      default = {};
      extensible = true;
      description = "Typed systemd .target units.";
    };

    sockets = lib.mkOption {
      type = systemdTypes.sockets;
      default = {};
      extensible = true;
      description = "Typed systemd .socket units.";
    };

    timers = lib.mkOption {
      type = systemdTypes.timers;
      default = {};
      extensible = true;
      description = "Typed systemd .timer units.";
    };

    paths = lib.mkOption {
      type = systemdTypes.paths;
      default = {};
      extensible = true;
      description = "Typed systemd .path units.";
    };

    slices = lib.mkOption {
      type = systemdTypes.slices;
      default = {};
      extensible = true;
      description = "Typed systemd .slice units.";
    };

    mounts = lib.mkOption {
      type = systemdTypes.mounts;
      default = [];
      extensible = true;
      description = "Typed systemd .mount units. Keyed by `where`, not by name.";
    };

    automounts = lib.mkOption {
      type = systemdTypes.automounts;
      default = [];
      extensible = true;
      description = "Typed systemd .automount units. Keyed by `where`, not by name.";
    };

    units = lib.mkOption {
      type = systemdTypes.units;
      default = {};
      internal = true;
      readOnly = true;
      description = "Derived rendering of the typed systemd unit declarations.";
    };
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

  options.system.build.systemdEtcEntryOwners = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    internal = true;
    readOnly = true;
    description = "Resolver-authenticated owner of each rendered systemd filesystem entry.";
  };

  options.system.build.systemdMaterializationData = lib.mkOption {
    type = lib.types.attrs;
    internal = true;
    default = let
      manifest = config.system.build.configManifest or null;
    in
      if manifest == null
      then {
        etc = config.system.build.systemdEtcEntries;
        jobScripts = config.system.build.systemdJobScripts;
      }
      else {
        inherit (manifest) etc jobScripts;
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

  options.system.build.systemdJobScriptOwners = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    internal = true;
    readOnly = true;
    description = "Resolver-authenticated owner of each rendered systemd executable script.";
  };

  options.system.build.systemdUnitActions = lib.mkOption {
    type = lib.types.attrsOf lib.types.attrs;
    internal = true;
    readOnly = true;
    description = "Pure per-unit reconcile records for the config manifest.";
  };

  config = lib.mkIf selected (let
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
      units = renderedUnits;
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
    unitOwners = typedUnitOwners;

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
    # but AOS has no `scope` unit type in the package-owned type library, so
    # there is no eval-time data source to check; revisit if
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
      ++ targetReloadTriggerAsserts
      ++ [
        {
          assertion = builtins.length config.systemd.providerManagerConfigurationPlans <= 1;
          message = "systemd manager configuration must have at most one authenticated provider owner";
        }
        {
          assertion = builtins.length config.systemd.providerNetworkConfigurationPlans <= 1;
          message = "systemd network configuration must have at most one authenticated provider owner";
        }
      ];

    warnings = reloadWithoutExecReloadWarnings;

    # Retain the rendered tree as an internal inspection projection. All
    # authored units enter through the typed category options above.
    systemd.units = renderedUnits;

    # Provider-owned units are rendered by the same compiled implementation
    # used at runtime. Its manifest is the only filename authority for those
    # entries; the assembler validates bytes, links, and collisions with the
    # ordinary module-rendered tree before publishing the boot unit directory.
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
    system.build.systemdEtcEntryOwners =
      systemdLib.unitsToOwnership pureSystemUnits unitOwners;
    system.build.systemdJobScriptOwners = let
      scriptOwner = key: let
        matchingUnits =
          builtins.filter
          (unit: lib.hasPrefix "${unit}:" key)
          (builtins.attrNames unitOwners);
      in
        if builtins.length matchingUnits == 1
        then unitOwners.${builtins.head matchingUnits}
        else throw "systemd executable script ${key} does not identify exactly one unit";
    in
      lib.mapAttrs (key: _: scriptOwner key) config.system.build.systemdJobScripts;
    system.build.systemdUnitOwners = unitOwners;
    system.build.systemdUnitActions = typedUnitActions;

    # Route the rendered unit directory through environment.etc so
    # the EROFS image carries it as a real directory of symlinks (the
    # composefs dump script's `mode == "symlink"` + `os.path.isdir(source)`
    # branch recurses — spec v12 §5.2). At runtime, this directory
    # merges with the per-generation config lower's `/etc/systemd/system/`
    # without one side shadowing the other.
  });
}
