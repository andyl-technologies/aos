##! lib/default.nix — AOS library entry point
##!
##! Composes all library modules into a single attribute set.
##! Usage: `let lib = import ./lib { system = "aarch64-linux"; }; in ...`
##!
##! The `system` parameter is threaded through to all derivation builders
##! (mkDerivation, mkShell, fetchurl, fetchgit, fetchCargoDeps, fetchCargoVendor, fetchGoModules)
##! so that every package targets the correct platform.
##!
##! The optional `bash` parameter (a derivation) causes all builders to use
##! the AOS-built bash instead of `/bin/sh`. When `null` (early bootstrap),
##! `/bin/sh` is used as a fallback.
##!
##! Submodule semantics — the fixpoint below:
##!
##!   lib/types.nix's `submodule` type delegates to `evalSubmodule`, which
##!   closes over `modules.evalModules`, which is constructed from
##!   `lib/modules.nix` with `types` as a parameter. This is a mutual
##!   recursion between `types` and `modules` broken by Nix's laziness:
##!   neither forces the other until an actual submodule merge fires
##!   during user-module evaluation, by which point the whole let block
##!   has been constructed. `evalSubmodule` passes `lib = finalLib` into
##!   the nested evalModules so any deeper submodules also get the real
##!   evaluator, and threads the attribute name of an `attrsOf` /
##!   `listOf` submodule through `specialArgs.name` so ported nixpkgs
##!   modules that write `{ name, config, ... }: ...` keep working.
{
  system,
  bash ? null,
}: let
  trivial = import ./trivial.nix;
  lists = import ./lists.nix;
  attrsets = import ./attrsets.nix;
  strings = import ./strings.nix;

  # --- Fixpoint: types and modules are mutually recursive --------------
  #
  # `types` takes `evalSubmodule` (a callback that knows how to evaluate
  # nested modules) as a lazy thunk. `modules` takes `types` as a lazy
  # thunk. `evalSubmodule` closes over `modules` and `finalLib`. None
  # of these three forces the others until a submodule merge is invoked,
  # which only happens during user-module evaluation when the whole
  # let-block has been fully resolved. This gives us real nixpkgs-style
  # submodule semantics (defaults, mkIf/mkMerge/mkDefault inside
  # submodules, per-option type checking) without tearing the lib into
  # two bootstrap phases.

  types = import ./types.nix {inherit evalSubmodule;};
  modules = import ./modules.nix {
    inherit
      trivial
      lists
      attrsets
      strings
      types
      ;
  };

  evalSubmodule = moduleArgs: loc: defs: let
    # `submodule [m1 m2 m3]` and `submodule m` should both work; nixpkgs
    # accepts either a single module or a list of modules.
    baseModules =
      if builtins.isList moduleArgs
      then moduleArgs
      else [moduleArgs];

    # Each definition contributes a `config = def.value` module, so the
    # submodule's option declarations (defaults, types, mkIf/mkMerge)
    # process it as a normal module input.
    applyInheritedPriority = priority: value:
      if priority == 100
      then value
      else if builtins.isAttrs value && value ? _type && value._type == "override"
      then value
      else if builtins.isAttrs value && value ? _type && value._type == "if"
      then value // {_value = applyInheritedPriority priority value._value;}
      else if builtins.isAttrs value && value ? _type && value._type == "merge"
      then value // {_values = builtins.map (applyInheritedPriority priority) value._values;}
      else if builtins.isAttrs value
      then builtins.mapAttrs (_: applyInheritedPriority priority) value
      else {
        _type = "override";
        _priority = priority;
        _value = value;
      };
    defModule = d: {
      _file = d.file or "<anonymous submodule definition>";
      config =
        applyInheritedPriority (
          if
            builtins.elem (d.provenance or "@base") ["@host" "@runtime"]
            && (d._priority or 100) == 75
          then 100
          else d._priority or 100
        )
        d.value;
    };
    baseDefModules = builtins.map defModule (builtins.filter
      (d:
        builtins.elem
        (d.provenance or "@base")
        ["@base" "@host-import" "@runtime-import"])
      defs);
    operatorDefModules = builtins.map defModule (builtins.filter
      (d: (d.provenance or "@base") == "@host")
      defs);
    runtimeDefModules = builtins.map defModule (builtins.filter
      (d: (d.provenance or "@base") == "@runtime")
      defs);
    packageDefRecords =
      builtins.map (d: {
        name = strings.removePrefix "package:" d.provenance;
        module = defModule d;
        authorization = d.authorization;
      }) (builtins.filter
        (d: strings.hasPrefix "package:" (d.provenance or "@base"))
        defs);

    # For `attrsOf (submodule ...)` and `listOf (submodule ...)`, the
    # last element of `loc` is the attribute name / list index. Nixpkgs-
    # style submodule modules written as `{ name, config, ... }: ...`
    # expect this as an implicit specialArg. Thread it through.
    implicitName =
      if loc == []
      then null
      else builtins.elemAt loc (builtins.length loc - 1);
    specialArgs =
      if implicitName != null
      then {name = implicitName;}
      else {};

    evaluated = modules.evalModules {
      modules = baseModules ++ baseDefModules;
      # Passing the fully-wired finalLib ensures any nested submodule
      # types inside `baseModules` see the upgraded `types.submodule`
      # and also recursively delegate to `evalSubmodule`.
      lib = finalLib;
      inherit specialArgs;
      operatorModules = operatorDefModules;
      runtimeModules = runtimeDefModules;
      packageModules = packageDefRecords;
      enforcePackageAuthorization = false;
    };
  in
    evaluated.config;

  # Module-namespacing and contributable-surface helpers.
  # Pure data over evaluated module sets / module values; takes the wired
  # `types` and `mkOption` so callers reach them at `lib.mkPackageRoot` etc.
  namespacing = import ./namespacing.nix {
    inherit types;
    inherit (modules) mkOption;
  };

  # Version-stable primitive contracts shared by independently authenticated
  # package modules. Logical service schemas remain package-owned.
  serviceTypes = import ./service-types.nix {
    inherit types;
    inherit (modules) mkOption;
  };

  platformMod = import ./platform.nix;
  derivations = import ./derivations.nix {inherit system bash;};
  hardening = import ./hardening.nix;
  checks = import ./testing/checks.nix;

  # Format helpers (nixpkgs' `pkgs.formats` analog). Each entry in this
  # attrset is a factory that receives `{ lib, pkgs, … }` at call time
  # and returns `{ type; generate; … }`. Keeping them lazy — not
  # pre-applied — avoids threading `pkgs` through `lib/default.nix`,
  # which is deliberately `pkgs`-less (see the file header).
  formats = import ./formats;

  finalLib =
    trivial
    // lists
    // attrsets
    // strings
    // {
      inherit types system;
      inherit serviceTypes;
      inherit
        (platformMod)
        mkPlatform
        cpus
        kernels
        satisfies
        canRun
        canBuildOn
        platformIsCompatible
        constraintsCompatible
        executionTargets
        resolveTarget
        mkPlatformFromConstraints
        ;
      platform = platformMod.mkPlatform system;
      inherit
        (modules)
        evalModules
        mkOption
        mkIf
        mkMerge
        mkOverride
        mkDefault
        mkForce
        mkOrder
        mkBefore
        mkAfter
        mkEnableOption
        mkPackageOption
        ;
      inherit
        (derivations)
        mkDerivation
        mkShell
        fetchurl
        fetchgit
        fetchCargoDeps
        fetchCargoVendor
        fetchGoModules
        fetchNpmDeps
        fetchBazelDeps
        fakeHash
        ;

      # Phase manipulation helpers from derivations module
      inherit
        (derivations)
        replacePhase
        addPhaseAfter
        addPhaseBefore
        removePhase
        ;

      # Derivation path helpers (isDerivation is already pulled in via the
      # `trivial //` spread above, so no extra inherit is needed for it).
      inherit
        (derivations)
        getOutput
        getBin
        getDev
        getExe
        getExe'
        ;

      # Nixpkgs-style top-level helpers that ported code expects at
      # `lib.mkOptionType` / `lib.mergeEqualOption`. Both live in
      # `lib/types.nix` because they are tightly coupled to how merge
      # functions are written.
      inherit
        (types)
        mkOptionType
        mergeEqualOption
        ;

      # Check composition helper (pure data, no deps) for use in modules
      inherit (checks) composeChecks;

      # Namespacing and contributable-surface helpers.
      inherit
        (namespacing)
        optionSurface
        contributableSurface
        mkPackageRoot
        mountPackageModules
        ;

      # Compiler-hardening token vocabulary and set algebra. Used by the
      # stdenv to bake the cc-wrapper's default policy and by derivations.nix
      # to compute each package's effective AOS_HARDENING_ENABLE.
      inherit hardening;

      # Structured-config format helpers. Each factory takes `{ lib,
      # pkgs, … }` at call time and returns `{ type; generate; }`.
      # See `lib/formats/` (aggregated via `lib/formats/default.nix`)
      # for the individual factories: `json.nix`, `yaml.nix`, and `toml.nix`.
      inherit formats;

      # Re-export submodules for direct access when needed
      inherit
        trivial
        lists
        attrsets
        strings
        modules
        derivations
        checks
        ;
    };
in
  finalLib
