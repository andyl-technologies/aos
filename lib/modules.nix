# lib/modules.nix — Module evaluation engine
#
# Takes { trivial, lists, attrsets, strings, types } and returns
# { evalModules, mkOption, mkIf }.
#
# Module format:
#   { config, pkgs, lib, ... }: {
#     options = { ... };   # Option declarations with mkOption
#     config  = { ... };   # Option definitions (values)
#   }
#
# evalModules evaluates a list of modules, merging their option declarations
# and config definitions according to type-specific merge functions.
# Later modules override earlier ones (last-writer-wins for scalar types,
# concatenation for list types, recursive merge for attrset types).
#

{
  trivial,
  lists,
  attrsets,
  strings,
  types,
}:

let
  # ---------------------------------------------------------------------------
  # mkOption — declare a module option
  # ---------------------------------------------------------------------------
  # mkOption { type; default; description; }
  #
  # Returns a marker attrset that evalModules recognizes as an option declaration.
  mkOption =
    {
      type ? types.anything,
      default ? null,
      description ? "",
      example ? null,
      readOnly ? false,
      apply ? null,
      visible ? true,
    }:
    {
      _type = "option";
      inherit
        type
        default
        description
        example
        readOnly
        apply
        visible
        ;
    };

  # ---------------------------------------------------------------------------
  # mkIf — conditional configuration
  # ---------------------------------------------------------------------------
  # mkIf condition attrset
  #
  # Returns a marker that evalModules will process: if the condition is true,
  # the attrset is merged into config; if false, it is ignored.
  mkIf = condition: value: {
    _type = "if";
    _condition = condition;
    _value = value;
  };

  # ---------------------------------------------------------------------------
  # Internal: check if a value is an mkIf marker
  # ---------------------------------------------------------------------------
  isMkIf = v: builtins.isAttrs v && v ? _type && v._type == "if";

  # ---------------------------------------------------------------------------
  # Internal: check if a value is an option declaration
  # ---------------------------------------------------------------------------
  isOption = v: builtins.isAttrs v && v ? _type && v._type == "option";

  # ---------------------------------------------------------------------------
  # Internal: resolve mkIf markers in a config attrset
  # ---------------------------------------------------------------------------
  # Returns the attrset with all mkIf nodes resolved (kept or dropped).
  resolveIfs =
    value:
    if isMkIf value then
      if value._condition then resolveIfs value._value else { }
    else if builtins.isAttrs value then
      let
        names = builtins.attrNames value;
        resolved = builtins.listToAttrs (
          builtins.concatLists (
            builtins.map (
              name:
              let
                v = value.${name};
              in
              if isMkIf v then
                if v._condition then
                  [
                    {
                      inherit name;
                      value = resolveIfs v._value;
                    }
                  ]
                else
                  [ ]
              else
                [
                  {
                    inherit name;
                    value = resolveIfs v;
                  }
                ]
            ) names
          )
        );
      in
      resolved
    else
      value;

  # ---------------------------------------------------------------------------
  # Internal: collect option declarations from a module result
  # ---------------------------------------------------------------------------
  # Walks the `options` attrset and builds a flat map of option paths to
  # their declarations.
  collectOptions =
    prefix: optionTree:
    if isOption optionTree then
      [
        {
          path = prefix;
          option = optionTree;
        }
      ]
    else if builtins.isAttrs optionTree then
      builtins.concatLists (
        builtins.map (name: collectOptions (prefix ++ [ name ]) optionTree.${name}) (
          builtins.attrNames optionTree
        )
      )
    else
      [ ];

  # ---------------------------------------------------------------------------
  # Internal: extract a value at a given path from an attrset
  # ---------------------------------------------------------------------------
  getPath =
    path: attrs:
    builtins.foldl' (
      acc: key: if builtins.isAttrs acc && builtins.hasAttr key acc then acc.${key} else null
    ) attrs path;

  # ---------------------------------------------------------------------------
  # Internal: set a value at a given path in a nested attrset
  # ---------------------------------------------------------------------------
  setPath =
    path: value:
    let
      len = builtins.length path;
      go = i: if i >= len then value else { ${builtins.elemAt path i} = go (i + 1); };
    in
    if len == 0 then value else go 0;

  # ---------------------------------------------------------------------------
  # Internal: collect definitions at a path, traversing through mkIf nodes
  # ---------------------------------------------------------------------------
  # Returns a list of { file; value; condition?; } records.
  # mkIf nodes are not resolved eagerly; instead the condition is attached
  # to each definition and evaluated lazily during the merge phase.
  collectDefsAtPath =
    path: config: file:
    if isMkIf config then
      # Wrap inner defs with the condition (AND with any existing condition)
      builtins.map (
        d:
        d
        // {
          condition = if d ? condition then d.condition && config._condition else config._condition;
        }
      ) (collectDefsAtPath path config._value file)
    else if builtins.length path == 0 then
      [
        {
          inherit file;
          value = config;
        }
      ]
    else if builtins.isAttrs config then
      let
        key = builtins.head path;
        rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
      in
      if builtins.hasAttr key config then collectDefsAtPath rest config.${key} file else [ ]
    else
      [ ];

  # ---------------------------------------------------------------------------
  # Internal: deep merge two attrsets (for building the final config tree)
  # ---------------------------------------------------------------------------
  deepMerge =
    lhs: rhs:
    if builtins.isAttrs lhs && builtins.isAttrs rhs then
      let
        lNames = builtins.attrNames lhs;
        rNames = builtins.attrNames rhs;
        allNames =
          let
            combined = lNames ++ rNames;
            dedup =
              acc: remaining:
              if remaining == [ ] then
                acc
              else
                let
                  h = builtins.elemAt remaining 0;
                  t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
                in
                if builtins.any (x: x == h) acc then dedup acc t else dedup (acc ++ [ h ]) t;
          in
          dedup [ ] combined;
      in
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value =
            let
              lHas = builtins.hasAttr name lhs;
              rHas = builtins.hasAttr name rhs;
            in
            if lHas && rHas then
              deepMerge lhs.${name} rhs.${name}
            else if rHas then
              rhs.${name}
            else
              lhs.${name};
        }) allNames
      )
    else
      rhs;

  # ---------------------------------------------------------------------------
  # Internal: import and evaluate a single module
  # ---------------------------------------------------------------------------
  # A module can be:
  #   1. A path to a .nix file containing a function or attrset
  #   2. A function { config, pkgs, lib, ... }: { options = ...; config = ...; }
  #   3. An attrset { options = ...; config = ...; }
  #
  # Returns { options :: attrset; config :: attrset; _file :: string; }
  evalModule =
    {
      config,
      pkgs,
      lib,
      extraArgs,
    }:
    mod:
    let
      # Determine the file path for error messages
      file =
        if builtins.isPath mod then
          builtins.toString mod
        else if builtins.isString mod then
          mod
        else if builtins.isAttrs mod && mod ? _file then
          mod._file
        else
          "<anonymous module>";

      # Load the module if it is a path
      loaded =
        if builtins.isPath mod || (builtins.isString mod && builtins.pathExists mod) then
          import mod
        else
          mod;

      # Evaluate the module (call it if it is a function)
      args = {
        inherit config pkgs lib;
      }
      // extraArgs;
      evaluated =
        if builtins.isFunction loaded then
          let
            fArgs = builtins.functionArgs loaded;
            # Build the argument set, including only what the function accepts
            callArgs =
              if fArgs == { } then
                args # No formals, pass everything (variadic)
              else
                builtins.intersectAttrs fArgs args
                // (
                  # If the function accepts `...`, pass everything
                  # functionArgs returns {} for both no-args and ...-args
                  # A function with `...` will accept extra args fine
                  { });
          in
          loaded (args // { _file = file; })
        else
          loaded;

      # Normalize: ensure options and config keys exist
      result = {
        options = evaluated.options or { };
        config =
          evaluated.config or (
            # If there is no explicit `config` key, treat all non-special keys as config
            builtins.removeAttrs evaluated [
              "options"
              "imports"
              "require"
              "_file"
              "_type"
            ]
          );
        _file = file;
        imports = evaluated.imports or [ ];
      };
    in
    result;

  # ---------------------------------------------------------------------------
  # evalModules — the main entry point
  # ---------------------------------------------------------------------------
  # evalModules { modules; pkgs; lib; extraArgs; }
  #
  # Evaluates a list of modules:
  #   1. Import each module, passing { config, pkgs, lib }
  #   2. Collect all option declarations
  #   3. Collect all config definitions
  #   4. Merge config values according to type merge functions
  #   5. Process mkIf conditionals
  #   6. Return the final merged config attrset
  #
  evalModules =
    {
      modules,
      pkgs ? { },
      lib ? { },
      extraArgs ? { },
    }:
    let
      # Build the lib to pass to modules (self-referential with config)
      moduleLib =
        if lib == { } then
          trivial
          // lists
          // attrsets
          // strings
          // {
            inherit types;
            inherit mkOption mkIf;
          }
        else
          lib;

      # --- Phase 1: Evaluate all modules ---
      # Use a fixed-point to allow modules to reference the final config.
      # The config is computed lazily, so modules can use `config.foo` in their
      # config section and it will resolve to the merged value.
      result =
        let
          # Collect all modules including imports (recursive)
          collectModules =
            mods:
            builtins.concatLists (
              builtins.map (
                mod:
                let
                  evaled = evalModule {
                    config = finalConfig;
                    pkgs = pkgs;
                    lib = moduleLib;
                    inherit extraArgs;
                  } mod;
                  # Imports are processed first so that the importing module's
                  # config values come later in the list and win with
                  # last-writer-wins merge semantics.
                in
                collectModules evaled.imports ++ [ evaled ]
              ) mods
            );

          evaluatedModules = collectModules modules;

          # --- Phase 2: Collect all option declarations ---
          allOptionDecls = builtins.concatLists (
            builtins.map (m: collectOptions [ ] m.options) evaluatedModules
          );

          # Build a map from option path (as string) to the option declaration.
          # Later declarations override earlier ones.
          optionMap = builtins.foldl' (
            acc: decl:
            let
              key = builtins.concatStringsSep "." decl.path;
            in
            acc // { ${key} = decl; }
          ) { } allOptionDecls;

          # --- Phase 3: Collect config definitions for each option ---
          # For each declared option, find all config values at that path
          # from all modules, traversing through mkIf nodes without forcing
          # their conditions (conditions are evaluated lazily during merge).
          configForOption =
            decl:
            builtins.concatLists (
              builtins.map (m: collectDefsAtPath decl.path m.config m._file) evaluatedModules
            );

          # --- Phase 4: Merge config values for each option ---
          mergedOptions = builtins.listToAttrs (
            builtins.map (
              key:
              let
                decl = optionMap.${key};
                defs = configForOption decl;
                optType = decl.option.type;
                pathStr = builtins.concatStringsSep "." decl.path;

                # Filter out conditional definitions whose condition is false
                activeDefs = builtins.filter (d: !(d ? condition) || d.condition) defs;

                # Determine the merged value
                mergedValue =
                  if activeDefs == [ ] then
                    # No definitions: use default if available
                    if decl.option.default != null then
                      decl.option.default
                    else
                      throw "The option '${pathStr}' is used but has no definition and no default value."
                  else
                    # Merge all active definitions using the type's merge function
                    let
                      rawMerged = optType.merge decl.path activeDefs;
                    in
                    rawMerged;

                # Apply the apply function if present
                finalValue = if decl.option.apply != null then decl.option.apply mergedValue else mergedValue;
              in
              {
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
          # Convert the flat merged options back into a nested attrset.
          finalConfig =
            builtins.foldl' (
              acc: key:
              let
                entry = mergedOptions.${key};
              in
              deepMerge acc (setPath entry.path entry.finalValue)
            ) { } (builtins.attrNames mergedOptions)
            // {
              # Include _module.args for passing extra arguments to modules
              _module = {
                args = extraArgs;
              };
            };

          # Also merge in any config values that do not correspond to declared options.
          # This allows "freeform" config for extensibility.
          # resolveIfs is applied here; this is safe because values are accessed
          # lazily through the fixpoint — by the time a condition like
          # config.aos.firewall.enable is accessed, the fixpoint is established.
          allConfigMerged = builtins.foldl' (
            acc: m: deepMerge acc (resolveIfs m.config)
          ) { } evaluatedModules;

          # The final config is the declared options merged with freeform config,
          # where declared options take precedence (they have proper merge semantics).
          configWithFreeform = deepMerge allConfigMerged finalConfig;

        in
        {
          config = configWithFreeform;
          options = optionMap;
          _modules = evaluatedModules;

          # Convenience accessor: get the type-checked config
          # (same as config, but provided for API clarity)
          _type = "evaluatedModules";
        };

    in
    result;

in
{
  inherit evalModules mkOption mkIf;
}
