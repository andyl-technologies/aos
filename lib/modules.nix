##! lib/modules.nix — Module evaluation engine
##!
##! Takes `{ trivial, lists, attrsets, strings, types }` and returns
##! `{ evalModules, mkOption, mkIf, mkMerge, mkOverride, mkDefault, mkForce,
##!   mkOrder, mkBefore, mkAfter }`.
##!
##! Module format:
##!
##!     { config, pkgs, lib, ... }: {
##!       options = { ... };   # Option declarations with mkOption
##!       config  = { ... };   # Option definitions (values)
##!     }
##!
##! evalModules evaluates a list of modules, merging their option declarations
##! and config definitions according to type-specific merge functions.
##! Later modules override earlier ones (last-writer-wins for scalar types,
##! concatenation for list types, recursive merge for attrset types).
##!
##! Priority system:
##!
##!     mkDefault value       — priority 1000 (lowest precedence)
##!     (normal value)        — priority 100
##!     mkForce value         — priority 50 (highest precedence)
##!     mkOverride N value    — explicit priority N (lower = higher precedence)
##!
##! Ordering system (for listOf types):
##!
##!     mkBefore value        — order 500 (sorts earlier)
##!     (normal value)        — order 1000
##!     mkAfter value         — order 1500 (sorts later)
{
  trivial,
  lists,
  attrsets,
  strings,
  types,
}: let
  # ---------------------------------------------------------------------------
  # mkOption — declare a module option
  # ---------------------------------------------------------------------------
  # Sentinel value for "no default provided" (distinct from default = null)
  _noDefault = {
    _type = "noDefault";
  };
  isNoDefault = v: builtins.isAttrs v && v ? _type && v._type == "noDefault";

  mkOption = {
    type ? types.anything,
    default ? _noDefault,
    description ? "",
    example ? null,
    readOnly ? false,
    apply ? null,
    visible ? true,
    # `internal` is accepted for nixpkgs compatibility. Options marked
    # internal are not meant for end users (they're module-internal
    # plumbing). AOS doesn't generate option docs yet, so the flag is
    # stored but otherwise ignored. Ports of nixpkgs code frequently
    # set this on `*.unit` / `*.jobScripts` fields.
    internal ? false,
  }: {
    _type = "option";
    inherit
      type
      default
      description
      example
      readOnly
      apply
      visible
      internal
      ;
  };

  # ---------------------------------------------------------------------------
  # mkIf — conditional configuration
  # ---------------------------------------------------------------------------
  mkIf = condition: value: {
    _type = "if";
    _condition = condition;
    _value = value;
  };

  # ---------------------------------------------------------------------------
  # mkMerge — merge multiple config attrsets
  # ---------------------------------------------------------------------------
  mkMerge = values: {
    _type = "merge";
    _values = values;
  };

  # ---------------------------------------------------------------------------
  # mkOverride — set a value with explicit priority
  # ---------------------------------------------------------------------------
  # Lower priority number = higher precedence.
  # Normal values have priority 100.
  mkOverride = priority: value: {
    _type = "override";
    _priority = priority;
    _value = value;
  };

  mkDefault = value: mkOverride 1000 value;
  mkForce = value: mkOverride 50 value;

  # ---------------------------------------------------------------------------
  # mkOrder — set ordering priority for list elements
  # ---------------------------------------------------------------------------
  mkOrder = priority: value: {
    _type = "order";
    _priority = priority;
    _value = value;
  };

  mkBefore = value: mkOrder 500 value;
  mkAfter = value: mkOrder 1500 value;

  # ---------------------------------------------------------------------------
  # mkEnableOption — shorthand for `enable = mkOption { type = bool; ... };`
  # ---------------------------------------------------------------------------
  #
  # Matches nixpkgs' `lib.mkEnableOption` (lib/options.nix). Produces a
  # boolean option that defaults to `false` and has a `description`
  # phrased as "Whether to enable <description>." — which is the
  # conventional way NixOS modules introduce feature toggles.
  mkEnableOption = nameOrDescription:
    mkOption {
      type = types.bool;
      default = false;
      example = true;
      description = "Whether to enable ${nameOrDescription}.";
    };

  # ---------------------------------------------------------------------------
  # mkPackageOption — shorthand for a typed package-valued option
  # ---------------------------------------------------------------------------
  #
  # Matches nixpkgs' `lib.mkPackageOption` (lib/options.nix). Produces a
  # `types.package` option whose default is `pkgs.<name>` (walking a
  # list of path components if `name` is a list, to support nested
  # package sets), with a description that spells out how to override.
  #
  # Arguments:
  #   pkgs            — the package set to look the default up in.
  #                     Typically the caller passes its own `pkgs`.
  #   name            — string or list of strings identifying the default
  #                     package, e.g. "coreutils" or [ "python3" "pkgs" "numpy" ].
  #   default         — override the automatic pkgs.${name} default.
  #   nullable        — when true, the option type becomes `nullOr package`
  #                     and the default (if not provided) is `null`.
  #   example         — example value shown in docs; defaults to the default.
  #   extraDescription — extra prose appended to the generated description.
  mkPackageOption = pkgsArg: name: {
    default ? null,
    nullable ? false,
    example ? null,
    extraDescription ? "",
  }: let
    nameList =
      if builtins.isList name
      then name
      else [name];
    displayName = builtins.concatStringsSep "." nameList;
    resolveDefault = builtins.foldl' (acc: n: acc.${n}) pkgsArg nameList;
    actualDefault =
      if default != null
      then default
      else if nullable
      then null
      else resolveDefault;
  in
    mkOption {
      type =
        if nullable
        then types.nullOr types.package
        else types.package;
      default = actualDefault;
      example =
        if example != null
        then example
        else actualDefault;
      description = ''
        The ${displayName} package to use.${
          if extraDescription != ""
          then "\n\n${extraDescription}"
          else ""
        }
      '';
    };

  # ---------------------------------------------------------------------------
  # Internal: type predicates
  # ---------------------------------------------------------------------------
  isMkIf = v: builtins.isAttrs v && v ? _type && v._type == "if";
  isMkMerge = v: builtins.isAttrs v && v ? _type && v._type == "merge";
  isOverride = v: builtins.isAttrs v && v ? _type && v._type == "override";
  isOption = v: builtins.isAttrs v && v ? _type && v._type == "option";
  isOrder = v: builtins.isAttrs v && v ? _type && v._type == "order";

  # ---------------------------------------------------------------------------
  # Internal: resolve mkIf and mkMerge markers in a config attrset
  # ---------------------------------------------------------------------------
  resolveIfs = value:
    if isMkIf value
    then
      if value._condition
      then resolveIfs value._value
      else {}
    else if isMkMerge value
    then builtins.foldl' deepMerge {} (builtins.map resolveIfs value._values)
    else if isOverride value
    then resolveIfs value._value
    else if builtins.isAttrs value
    then let
      names = builtins.attrNames value;
      resolved = builtins.listToAttrs (
        builtins.concatLists (
          builtins.map (
            name: let
              v = value.${name};
            in
              if isMkIf v
              then
                if v._condition
                then [
                  {
                    inherit name;
                    value = resolveIfs v._value;
                  }
                ]
                else []
              else [
                {
                  inherit name;
                  value = resolveIfs v;
                }
              ]
          )
          names
        )
      );
    in
      resolved
    else value;

  # ---------------------------------------------------------------------------
  # Internal: collect option declarations from a module result
  # ---------------------------------------------------------------------------
  collectOptions = prefix: optionTree:
    if isOption optionTree
    then [
      {
        path = prefix;
        option = optionTree;
      }
    ]
    else if builtins.isAttrs optionTree
    then
      builtins.concatLists (
        builtins.map (name: collectOptions (prefix ++ [name]) optionTree.${name}) (
          builtins.attrNames optionTree
        )
      )
    else [];

  # ---------------------------------------------------------------------------
  # Internal: extract a value at a given path from an attrset
  # ---------------------------------------------------------------------------
  getPath = path: attrs:
    builtins.foldl' (
      acc: key:
        if builtins.isAttrs acc && builtins.hasAttr key acc
        then acc.${key}
        else null
    )
    attrs
    path;

  # ---------------------------------------------------------------------------
  # Internal: set a value at a given path in a nested attrset
  # ---------------------------------------------------------------------------
  setPath = path: value: let
    len = builtins.length path;
    go = i:
      if i >= len
      then value
      else {${builtins.elemAt path i} = go (i + 1);};
  in
    if len == 0
    then value
    else go 0;

  # ---------------------------------------------------------------------------
  # Internal: collect definitions at a path, traversing mkIf and mkMerge nodes
  # ---------------------------------------------------------------------------
  collectDefsAtPath = path: config: file:
    if isMkMerge config
    then builtins.concatLists (builtins.map (v: collectDefsAtPath path v file) config._values)
    else if isMkIf config
    then
      builtins.map (
        d:
          d
          // {
            condition =
              if d ? condition
              then d.condition && config._condition
              else config._condition;
          }
      ) (collectDefsAtPath path config._value file)
    else if builtins.length path == 0
    then [
      {
        inherit file;
        value = config;
      }
    ]
    else if builtins.isAttrs config
    then let
      key = builtins.head path;
      rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
    in
      if builtins.hasAttr key config
      then collectDefsAtPath rest config.${key} file
      else []
    else [];

  # ---------------------------------------------------------------------------
  # Internal: deep merge two attrsets (for building the final config tree)
  # ---------------------------------------------------------------------------
  deepMerge = lhs: rhs:
    if builtins.isAttrs lhs && builtins.isAttrs rhs
    then let
      lNames = builtins.attrNames lhs;
      rNames = builtins.attrNames rhs;
      allNames = let
        combined = lNames ++ rNames;
        dedup = acc: remaining:
          if remaining == []
          then acc
          else let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
            if builtins.any (x: x == h) acc
            then dedup acc t
            else dedup (acc ++ [h]) t;
      in
        dedup [] combined;
    in
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = let
            lHas = builtins.hasAttr name lhs;
            rHas = builtins.hasAttr name rhs;
          in
            if lHas && rHas
            then deepMerge lhs.${name} rhs.${name}
            else if rHas
            then rhs.${name}
            else lhs.${name};
        })
        allNames
      )
    else rhs;

  # ---------------------------------------------------------------------------
  # Internal: build a nested options tree from a flat list of option
  # declarations, so module functions can take an `options` argument and
  # do things like `options.services.foo.isDefined`.
  # ---------------------------------------------------------------------------
  #
  # Each leaf in the produced tree is the raw option declaration decorated
  # with module-system metadata:
  #   {
  #     _type = "option";   # from the original mkOption call
  #     type; default; description; ...;
  #     isDefined = <bool>;                 # any definition beyond the default?
  #     definitions = [<raw def values>];   # unprocessed defs (pre-merge)
  #     value = <merged result>;            # lazy — same as config.<path>
  #   }
  #
  # The tree is lazy: walking it or looking up a specific leaf does not
  # force sibling leaves, and forcing a leaf only runs the merge for that
  # specific option. Module functions that don't ask for `options` in
  # their signature never pay the cost.
  mkOptionsTree = entries: let
    setAtPath = path: leaf: acc:
      if path == []
      then leaf
      else let
        key = builtins.head path;
        rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
        existing = acc.${key} or {};
      in
        acc // {${key} = setAtPath rest leaf existing;};
  in
    builtins.foldl' (
      tree: entry: let
        leaf =
          entry.option
          // {
            inherit (entry) path definitions;
            isDefined = entry.definitions != [];
            # `value` mirrors `config.<path>` — lazy, forced only on access.
            value = entry.finalValue;
          };
      in
        setAtPath entry.path leaf tree
    ) {} (builtins.attrValues entries);

  # ---------------------------------------------------------------------------
  # Internal: import and evaluate a single module
  # ---------------------------------------------------------------------------
  evalModule = {
    config,
    options,
    pkgs,
    lib,
    extraArgs,
  }: mod: let
    file =
      if builtins.isPath mod
      then builtins.toString mod
      else if builtins.isString mod
      then mod
      else if builtins.isAttrs mod && mod ? _file
      then mod._file
      else "<anonymous module>";

    loaded =
      if builtins.isPath mod || (builtins.isString mod && builtins.pathExists mod)
      then import mod
      else mod;

    args =
      {
        inherit config options pkgs lib;
      }
      // extraArgs;

    # `_module.args` propagation, ported from nixpkgs'
    # `lib/modules.nix:701-736` `applyModuleArgs` pattern.
    #
    # For each key the module function's argument pattern asks for,
    # build a lazy thunk that first looks the key up in the already-
    # built `args` attrset (which has caller-provided `extraArgs` /
    # `specialArgs` and the standard `config` / `options` / `pkgs` /
    # `lib`), and if absent, falls back to `config._module.args.${name}`.
    #
    # The critical trick is `mapAttrs` over `functionArgs loaded`: it
    # iterates only the KEYS of the function's argument pattern
    # (which are statically known — `functionArgs` does not force
    # `config`), and produces an attrset whose VALUES are lazy. This
    # breaks what would otherwise be an infinite recursion:
    #   args ← config._module.args ← modules' config ← modules' args
    # Only the specific module function body forcing `args.customPkg`
    # forces `config._module.args.customPkg`, which in turn forces
    # just the one setter module's contribution at that path.
    #
    # An older naive attempt — `args = … // (config._module.args or {})`
    # — cycled because `//` forces both operands to enumerate their
    # full key sets, which requires fully evaluating every module's
    # config._module.args contribution before any module's args can
    # be constructed.
    proxyArgs =
      if builtins.isFunction loaded
      then
        builtins.mapAttrs (
          name: _:
            args.${name}
            or config._module.args.${name}
        ) (builtins.functionArgs loaded)
      else {};

    evaluated =
      if builtins.isFunction loaded
      then loaded (args // proxyArgs // {_file = file;})
      else loaded;

    result = {
      options = evaluated.options or {};
      config =
        evaluated.config
        or (builtins.removeAttrs evaluated [
          "options"
          "imports"
          "require"
          "_file"
          "_type"
        ]);
      _file = file;
      imports = evaluated.imports or [];
    };
  in
    result;

  # ---------------------------------------------------------------------------
  # evalModules — the main entry point
  # ---------------------------------------------------------------------------
  # Parameters:
  #   modules    — list of module paths or attrsets to evaluate
  #   pkgs       — package set passed to all modules as `pkgs`
  #   lib        — library set passed to all modules as `lib`
  #   extraArgs  — additional arguments merged into module call args
  #   specialArgs — like extraArgs but semantically reserved for caller-provided
  #                 overrides (e.g. system-level config). Merged after extraArgs.
  evalModules = {
    modules,
    pkgs ? {},
    lib ? {},
    extraArgs ? {},
    specialArgs ? {},
  }: let
    moduleLib =
      if lib == {}
      then
        trivial
        // lists
        // attrsets
        // strings
        // {
          inherit types;
          inherit
            mkOption
            mkIf
            mkMerge
            mkOverride
            mkDefault
            mkForce
            ;
          inherit mkOrder mkBefore mkAfter;
        }
      else lib;

    result = let
      collectModules = mods:
        builtins.concatLists (
          builtins.map (
            mod: let
              evaled =
                evalModule {
                  config = finalConfig;
                  options = optionsTree;
                  pkgs = pkgs;
                  lib = moduleLib;
                  extraArgs = extraArgs // specialArgs;
                }
                mod;
            in
              collectModules evaled.imports ++ [evaled]
          )
          mods
        );

      evaluatedModules = collectModules modules;

      # Nested options tree, built from mergedOptions and fed back to
      # module functions via evalModule's `options` arg. This is the
      # AOS equivalent of nixpkgs' `{ config, options, ... }: …` pattern.
      # The tree is lazy: module functions that don't take `options`
      # never trigger its construction; modules that take it and access
      # a specific leaf only force that one leaf.
      optionsTree = mkOptionsTree mergedOptions;

      # --- Phase 2: Collect all option declarations ---
      allOptionDecls = builtins.concatLists (
        builtins.map (m: collectOptions [] m.options) evaluatedModules
      );

      optionMap =
        builtins.foldl' (
          acc: decl: let
            key = builtins.concatStringsSep "." decl.path;
          in
            acc // {${key} = decl;}
        ) {}
        allOptionDecls;

      # --- Phase 3: Collect config definitions for each option ---
      configForOption = decl:
        builtins.concatLists (
          builtins.map (m: collectDefsAtPath decl.path m.config m._file) evaluatedModules
        );

      # --- Phase 4: Merge config values for each option ---
      mergedOptions = builtins.listToAttrs (
        builtins.map (
          key: let
            decl = optionMap.${key};
            defs = configForOption decl;
            optType = decl.option.type;
            pathStr = builtins.concatStringsSep "." decl.path;

            # Filter out conditional definitions whose condition is false
            activeDefs = builtins.filter (d: !(d ? condition) || d.condition) defs;

            # Unwrap override markers and assign priorities
            unwrappedDefs =
              builtins.map (
                d:
                  if isOverride d.value
                  then
                    d
                    // {
                      value = d.value._value;
                      _priority = d.value._priority;
                    }
                  else d // {_priority = 100;}
              )
              activeDefs;

            # Find the lowest (winning) priority
            minPriority =
              builtins.foldl' (
                acc: d:
                  if d._priority < acc
                  then d._priority
                  else acc
              )
              9999
              unwrappedDefs;

            # Keep only definitions at the winning priority
            priorityFilteredDefs = builtins.filter (d: d._priority == minPriority) unwrappedDefs;

            # Enforce `readOnly`. Matches nixpkgs' behaviour at
            # `lib/modules.nix:1132-1144`: a read-only option may have
            # at most one definition — anything more is an error. This
            # intentionally runs BEFORE the merge so the error message
            # can list every conflicting def with its source file.
            _readOnlyCheck =
              if (decl.option.readOnly or false) && builtins.length priorityFilteredDefs > 1
              then
                throw ''
                  The option '${pathStr}' is read-only, but it has ${builtins.toString (builtins.length priorityFilteredDefs)} definitions:
                  ${builtins.concatStringsSep "\n" (
                    builtins.map (d: "  - in ${d.file or "<unknown>"}: ${builtins.toJSON d.value}") priorityFilteredDefs
                  )}
                ''
              else null;

            # Determine the merged value. `_readOnlyCheck` is forced
            # via `seq` so the throw above fires before the merge runs.
            mergedValue = builtins.seq _readOnlyCheck (
              if priorityFilteredDefs == []
              then
                if !(isNoDefault decl.option.default)
                then decl.option.default
                else throw "The option '${pathStr}' is used but has no definition and no default value."
              else let
                rawMerged = optType.merge decl.path priorityFilteredDefs;
              in
                rawMerged
            );

            # Apply the apply function if present
            finalValue =
              if decl.option.apply != null
              then decl.option.apply mergedValue
              else mergedValue;
          in {
            name = key;
            value = {
              path = decl.path;
              inherit finalValue;
              option = decl.option;
              definitions = defs;
            };
          }
        ) (builtins.attrNames optionMap)
      );

      # --- Phase 5: Build the final config attrset ---
      #
      # `_module.args` is seeded with the caller-provided `extraArgs` and
      # `specialArgs` and extended with any module's `config._module.args.X`
      # contribution via `allConfigMerged`. The proxy-args lookup in
      # `evalModule` falls back through `config._module.args.<name>` to
      # find either caller-provided or module-provided arguments.
      # This enables the nixpkgs `_module.args` pattern (audit fix 1.3).
      finalConfig =
        builtins.foldl' (
          acc: key: let
            entry = mergedOptions.${key};
          in
            deepMerge acc (setPath entry.path entry.finalValue)
        ) {} (builtins.attrNames mergedOptions)
        // {
          _module = {
            args =
              extraArgs
              // (allConfigMerged._module.args or {});
          };
        };

      allConfigMerged =
        builtins.foldl' (
          acc: m: deepMerge acc (resolveIfs m.config)
        ) {}
        evaluatedModules;

      configWithFreeform = deepMerge allConfigMerged finalConfig;
    in {
      config = configWithFreeform;
      # Exposed as the nested options tree (matching nixpkgs'
      # `result.options` shape) so external consumers can introspect
      # with the same `options.path.to.foo.isDefined` pattern that
      # modules use. The flat option-name → declaration map is still
      # available internally as `optionMap` for module-evaluation use.
      options = optionsTree;
      _modules = evaluatedModules;
      _type = "evaluatedModules";

      # Assertions and warnings from modules
      assertions = configWithFreeform.assertions or [];
      warnings = configWithFreeform.warnings or [];
    };
  in
    result;
in {
  inherit
    evalModules
    mkOption
    mkIf
    mkMerge
    ;
  inherit mkOverride mkDefault mkForce;
  inherit mkOrder mkBefore mkAfter;
  inherit mkEnableOption mkPackageOption;
}
