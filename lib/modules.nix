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
    defaultText ? null,
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
    # `contributable` is the capability-scoped contribution
    # surface" marker. It is a *pure declaration field* — the merge engine
    # (phases 3-6) completely ignores it, so setting it never changes how an
    # option's value is computed. Its sole purpose is to let a shared-root
    # OWNER curate which sub-paths NON-OWNER packages may write into: the
    # owner sets `contributable = true` on the curated extension points
    # (e.g. `nginx.virtualHosts`, `nginx.upstreams`) and leaves the root
    # node, `enable`, and global owner-only fields unmarked (the default,
    # `false`). For `attrsOf (submodule …)` the marker sits on the `attrsOf`
    # option node and is understood to inherit to every dynamic child; an
    # inner submodule option may re-declare `contributable = false` to punch
    # an owner-only hole. The flag is surfaced verbatim on the option record
    # (and via `evalModules`' `_optionDecls` result field) so the
    # publish-time options-only eval can fold it into the registry inverted
    # index; the actual provenance + reject ENFORCEMENT is resolver-side
    # (CS5), this engine only exposes the declared surface. Defaults `false`
    # so every existing option is owner-only and inert under this primitive.
    contributable ? false,
  }: {
    _type = "option";
    inherit
      type
      default
      defaultText
      description
      example
      readOnly
      apply
      visible
      internal
      contributable
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
  #
  # `provenance` is the engine-stamped, resolver-supplied origin marker for
  # the module this def came from (`null` for ordinary modules, `"operator"`
  # for a host.nix module the resolver passed via `operatorModules`). It is
  # threaded onto every emitted def UNCHANGED — exactly like `file` — and is
  # read ONLY at the priority-assignment step (phase 4) to lift operator defs
  # to the reserved tier-75 band. It is deliberately NOT derived from any
  # module-supplied attribute (`_file` / a module-body `_provenance`), so it
  # cannot be forged by a package (review M-forgeable-file).
  collectDefsAtPath = path: config: file: provenance:
    if isMkMerge config
    then builtins.concatLists (builtins.map (v: collectDefsAtPath path v file provenance) config._values)
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
      ) (collectDefsAtPath path config._value file provenance)
    else if builtins.length path == 0
    then [
      {
        inherit file provenance;
        value = config;
      }
    ]
    else if builtins.isAttrs config
    then let
      key = builtins.head path;
      rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
    in
      if builtins.hasAttr key config
      then collectDefsAtPath rest config.${key} file provenance
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

    # Accept `freeformType` and `strict` as top-level module attributes
    # and normalize them to `config._module.{freeformType,strict}`.
    # Matches nixpkgs' ergonomics where a module writes
    # `{ freeformType = pkgs.formats.json {}.type; … }` at the top level
    # rather than reaching into `config._module` directly.
    rawConfig =
      evaluated.config
      or (builtins.removeAttrs evaluated [
        "options"
        "imports"
        "require"
        "_file"
        "_type"
        "freeformType"
        "strict"
      ]);

    topLevelModuleMeta =
      (
        if evaluated ? freeformType
        then {freeformType = evaluated.freeformType;}
        else {}
      )
      // (
        if evaluated ? strict
        then {strict = evaluated.strict;}
        else {}
      );

    finalModuleConfig =
      if topLevelModuleMeta == {}
      then rawConfig
      else
        rawConfig
        // {
          _module = (rawConfig._module or {}) // topLevelModuleMeta;
        };

    result = {
      options = evaluated.options or {};
      config = finalModuleConfig;
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
    # `operatorModules` contains modules the
    # RESOLVER has authenticated as operator-provenance (the verified
    # `host.nix` store path). Every def these modules contribute is stamped
    # with `_provenance = "operator"` and lifted to the reserved priority-75
    # band (between `mkForce` and normal package contributions) at the
    # priority-assignment step, so the operator deterministically beats any
    # package contribution regardless of module order. Provenance is keyed to
    # a module's POSITION in this resolver-controlled list, NOT to its
    # forgeable `_file`, and does NOT propagate through `imports` — a package
    # cannot inject itself here, cannot forge `_provenance` in its own body
    # (the engine overwrites it), and cannot smuggle operator priority
    # through an imported child. Defaults `[]`, so with no `host.nix` the
    # second collect produces no modules and nothing is ever lifted —
    # behaviour is byte-identical to before this primitive. CS5 wires the
    # resolver to populate this from the verified host.nix path.
    operatorModules ? [],
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
      # Synthetic internal module that declares the three `_module.*`
      # options used by the engine itself. Without these declarations
      # strict-mode evaluation (see configWithFreeform below) would flag
      # `_module.args` contributions as undeclared, and there would be
      # nowhere to type-check `_module.freeformType`. Injected first in
      # `collectModules` so its declarations are available to all other
      # modules and submodules.
      internalModule = {
        _file = "<AOS internal: _module option declarations>";
        options._module = {
          args = mkOption {
            type = types.attrs;
            default = {};
            internal = true;
            description = ''
              Additional arguments passed to every module function.
              Seeded from `evalModules`' `extraArgs` / `specialArgs`
              parameters; modules may also extend it via
              `config._module.args.<name> = …`.
            '';
          };
          freeformType = mkOption {
            type = types.nullOr types.optionType;
            default = null;
            internal = true;
            description = ''
              When non-null, config paths with no matching option
              declaration are merged through this type's `merge`
              function rather than being rejected. Mirrors nixpkgs'
              RFC 0042 freeform modules. May also be written as a
              top-level module attribute (`{ freeformType = …; … }`).
            '';
          };
          strict = mkOption {
            type = types.bool;
            default = false;
            internal = true;
            description = ''
              When true and `_module.freeformType` is null, any config
              path with no matching option declaration throws at eval
              time with a readable error pointing at its source file.
              Scoped per evaluation — safe to turn on for a single
              submodule. May also be written as a top-level module
              attribute (`{ strict = true; … }`).
            '';
          };
        };
        # Seed `_module.args` with the caller's extraArgs/specialArgs so
        # the merged option value reflects the full arg-set exposed to
        # modules via `evalModule`'s `args = … // extraArgs;`.
        config._module.args = extraArgs // specialArgs;
      };

      # `collectModules provenance mods` recursively evaluates `mods`,
      # stamping each DIRECT member with the given `_provenance`. Imported
      # children are always collected with `null` provenance, so operator
      # provenance is confined to the exact modules the resolver supplied and
      # never leaks through an `imports` edge (review M-forgeable-file). The
      # `evaled // { _provenance = provenance; }` overwrite is what makes the
      # marker non-forgeable: any `_provenance` a module sets in its own body
      # is discarded here, and `collectDefsAtPath` later reads only this
      # engine-stamped value, never a module-body attribute.
      collectModules = provenance: mods:
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
              collectModules null evaled.imports ++ [(evaled // {_provenance = provenance;})]
          )
          mods
        );

      # Ordinary modules carry `null` provenance; operator (host.nix) modules
      # carry `"operator"`. Appended last so their tier-75 defs also win any
      # `lastValue` tie at equal priority, matching "the operator overrides".
      evaluatedModules =
        collectModules null ([internalModule] ++ modules)
        ++ collectModules "operator" operatorModules;

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
          builtins.map (m: collectDefsAtPath decl.path m.config m._file (m._provenance or null)) evaluatedModules
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

            # Unwrap override markers and assign priorities.
            #
            # A BARE def (no explicit `mkOverride`/`mkForce`/`mkDefault`) is
            # normally priority 100. The one exception is the
            # operator tier: a bare def whose engine-stamped provenance is
            # `"operator"` (it came from a resolver-supplied `host.nix`
            # module) is lifted to the reserved priority-75 band, so the
            # operator deterministically beats any package's normal-tier
            # contribution regardless of module order — without subtree-
            # wrapping (the `collectDefsAtPath` override-marker trap). An
            # operator def that DOES carry an explicit override marker keeps
            # that explicit priority (the operator can still `mkForce`/
            # `mkDefault` deliberately). With the default empty
            # `operatorModules`, no def ever has `"operator"` provenance, so
            # every bare def gets 100 exactly as before.
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
                  else
                    d
                    // {
                      _priority =
                        if (d.provenance or null) == "operator"
                        then 75
                        else 100;
                    }
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
                then
                  # Merge the default through the option type so type
                  # coercions and nested submodule field defaults apply.
                  optType.merge decl.path [
                    {
                      file = "<option-default:${pathStr}>";
                      value = decl.option.default;
                    }
                  ]
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
      # `_module.args` is declared by the synthetic internal module and
      # seeded with `extraArgs // specialArgs` there, so `mergedOptions`
      # already contains the caller-provided args folded with any
      # module's `_module.args.<name> = …` contribution via the `attrs`
      # type's merge. No post-hoc override is needed — the previous
      # `// { _module = { args = …; }; }` shim would have wiped the
      # sibling `_module.freeformType` / `_module.strict` values that
      # mergedOptions now places alongside `args`.
      finalConfig = builtins.foldl' (
        acc: key: let
          entry = mergedOptions.${key};
        in
          deepMerge acc (setPath entry.path entry.finalValue)
      ) {} (builtins.attrNames mergedOptions);

      allConfigMerged =
        builtins.foldl' (
          acc: m: deepMerge acc (resolveIfs m.config)
        ) {}
        evaluatedModules;

      # --- Phase 6: freeform / strict enforcement ---
      #
      # Opt-in per evaluation. When both `_module.freeformType` and
      # `_module.strict` are at their defaults (null / false), `config` is
      # exactly `finalConfig` — the per-option merge of every DECLARED option
      # (each option resolves its own mkIf/mkMerge via `collectDefsAtPath`).
      #
      # We deliberately do NOT fold in `allConfigMerged` here. That value is a
      # structural `deepMerge` of the raw module configs (via `resolveIfs`),
      # and its only effect on the result is to surface config set at
      # *undeclared* paths — which a well-formed module set never has. But
      # building it forces every config leaf to WHNF (to resolve mkIf markers),
      # including toplevel-only builders like `system.build.etcBasedir =
      # pkgs.runCommand …`. Forcing one declared option (e.g.
      # `system.build.configManifest`) would then force every sibling builder —
      # fatal under the on-host eval-only `pkgs`, which has no builder
      # functions. Using `finalConfig` keeps the result lazy per-option (so
      # broken-config paths stay inspectable, and the eval-only manifest never
      # touches the build graph) while remaining identical for any config whose
      # paths are all declared.
      #
      # When strict-mode or a freeformType is set, the walk runs and
      # collects every path in the raw module configs that has no
      # matching option declaration. Descent stops at any declared
      # option path (the option's own type owns strictness below that
      # point) and at the `_module` subtree (engine-internal).
      freeformType = finalConfig._module.freeformType or null;
      isStrict = finalConfig._module.strict or false;

      configWithFreeform =
        if freeformType == null && !isStrict
        then finalConfig
        else let
          declaredLeafSet = optionMap;

          declaredPrefixSet = let
            prefixesOf = key: let
              parts = strings.splitString "." key;
              n = builtins.length parts;
            in
              builtins.genList (
                i:
                  builtins.concatStringsSep "." (
                    builtins.genList (j: builtins.elemAt parts j) (i + 1)
                  )
              ) (n - 1);
            allPrefixes = builtins.concatLists (
              builtins.map prefixesOf (builtins.attrNames declaredLeafSet)
            );
          in
            builtins.listToAttrs (
              builtins.map (p: {
                name = p;
                value = true;
              })
              allPrefixes
            );

          findUndeclaredInModule = file: config: let
            go = path: val: let
              key = builtins.concatStringsSep "." path;
              descend = builtins.concatLists (
                builtins.map (name: go (path ++ [name]) val.${name})
                (builtins.attrNames val)
              );
            in
              if path == []
              then
                if builtins.isAttrs val
                then descend
                else []
              else if key == "_module"
              then []
              else if declaredLeafSet ? ${key}
              then []
              else if builtins.isAttrs val && declaredPrefixSet ? ${key}
              then descend
              else [
                {
                  inherit path file;
                  value = val;
                }
              ];
          in
            go [] config;

          undeclaredDefs = builtins.concatLists (
            builtins.map (
              m: findUndeclaredInModule m._file (resolveIfs m.config)
            )
            evaluatedModules
          );
        in
          if undeclaredDefs == []
          then finalConfig
          else if freeformType != null
          then let
            # Rebuild an attrset-tree from the flat undeclared def list
            # and hand it to the freeform type's merge as a single
            # synthetic definition. The type decides how to validate
            # and fold it. Declared options then win at conflicting
            # paths.
            setAt = path: value: acc:
              if path == []
              then value
              else let
                head = builtins.head path;
                rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
              in
                acc
                // {${head} = setAt rest value (acc.${head} or {});};
            freeformTree =
              builtins.foldl' (
                acc: d: setAt d.path d.value acc
              ) {}
              undeclaredDefs;
            merged = freeformType.merge [] [
              {
                file = "<freeform>";
                value = freeformTree;
              }
            ];
          in
            deepMerge merged finalConfig
          else let
            # isStrict == true (the remaining case)
            formatted = builtins.concatStringsSep "\n" (
              builtins.map (
                d: "  - '${builtins.concatStringsSep "." d.path}' (defined in ${d.file})"
              )
              undeclaredDefs
            );
          in
            throw ''
              The following option(s) are not declared:
              ${formatted}

              Because `_module.strict = true` on this evaluation, undeclared options are not allowed. Declare the option, or set `_module.freeformType` to a type that accepts these values.
            '';
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

      # Re-evaluate this module set with additional modules appended (matching
      # nixpkgs' `result.extendModules`). Used to overlay a fragment onto an
      # already-evaluated system without threading its original module list
      # back to the caller — e.g. the fleet test harness bakes per-VM identity
      # (`environment.etc` for hostname/network/ssh key) onto a machine's
      # system. `pkgs`/`lib`/`extraArgs`/`specialArgs`/`operatorModules` are
      # inherited from this evaluation unless overridden.
      extendModules = args: let
        extraModules = args.modules or [];
      in
        evalModules ({
            modules = modules ++ extraModules;
            inherit pkgs lib extraArgs specialArgs operatorModules;
          }
          // builtins.removeAttrs args ["modules"]);

      # The declared contributable option surface, flattened to one record
      # per declared option path, carrying the `contributable` marker. This
      # is the data the publish-time options-only eval folds into the
      # registry inverted index (`option-path → {owner@version,
      # contributable}`) so the resolver can authorize foreign writes
      # (CS5). It is a lazy, additive field — forced only when a publish
      # tool reads it — and is derived purely from `optionMap` (declarations),
      # never forcing any `config` value. `contributable` defaults `false`
      # (owner-only) for every option that does not opt in. `lib.optionSurface`
      # / `lib.contributableSurface` are the public accessors.
      _optionDecls = builtins.map (
        key: let
          decl = optionMap.${key};
        in {
          path = decl.path;
          pathStr = key;
          contributable = decl.option.contributable or false;
        }
      ) (builtins.attrNames optionMap);

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
