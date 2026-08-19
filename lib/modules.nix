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
  collectOptions = prefix: optionTree: file: provenance: authorization:
    if isOption optionTree
    then [
      {
        path = prefix;
        option = optionTree;
        inherit file provenance authorization;
      }
    ]
    else if builtins.isAttrs optionTree
    then
      builtins.concatLists (
        builtins.map (name: collectOptions (prefix ++ [name]) optionTree.${name} file provenance authorization) (
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
  # the module this def came from (`@base`, `@host`, or `package:<name>`).
  # The host stamp is assigned only through resolver `operatorModules`. It is
  # threaded onto every emitted def UNCHANGED — exactly like `file` — and is
  # read ONLY at the priority-assignment step (phase 4) to lift operator defs
  # to the reserved tier-75 band. It is deliberately NOT derived from any
  # module-supplied attribute (`_file` / a module-body `_provenance`), so it
  # cannot be forged by a package (review M-forgeable-file).
  collectDefsAtPath = path: config: file: provenance: authorization:
    if isMkMerge config
    then builtins.concatLists (builtins.map (v: collectDefsAtPath path v file provenance authorization) config._values)
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
      ) (collectDefsAtPath path config._value file provenance authorization)
    else if builtins.length path == 0
    then [
      {
        inherit file provenance authorization;
        value = config;
      }
    ]
    else if builtins.isAttrs config
    then let
      key = builtins.head path;
      rest = builtins.genList (i: builtins.elemAt path (i + 1)) (builtins.length path - 1);
    in
      if builtins.hasAttr key config
      then collectDefsAtPath rest config.${key} file provenance authorization
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
        ) (
          # Do not synthesize a throwing value for an optional argument that
          # the caller did not provide: its function-pattern default must win.
          # Required arguments retain the lazy `_module.args` fallback.
          attrsets.filterAttrs (
            name: hasDefault:
              !hasDefault || builtins.hasAttr name args
          ) (builtins.functionArgs loaded)
        )
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

    result =
      if
        builtins.isAttrs evaluated
        && (
          evaluated
          ? _provenance
          || (evaluated ? config && builtins.isAttrs evaluated.config && evaluated.config ? _provenance)
        )
      then throw "Module ${file} sets reserved attribute `_provenance`; provenance is resolver-controlled"
      else {
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
    # with engine provenance `@host` and lifted to the reserved priority-75
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
    # Config modules fetched from authenticated package outputs. Each record is
    # `{ name; module; configRoot; outputs; authorization; }`; every field is
    # resolver supplied from authenticated package metadata. `module` must be
    # `<configRoot>/module.nix`; recursive imports must remain path literals
    # below that root. `outputs` contains only `self` and authenticated runtime
    # dependency outputs, replacing ambient package-set traversal. Definitions
    # from the module and its imports are stamped `package:<name>` for artifact
    # ownership and checked against that exact authorization before merging.
    packageModules ? [],
    # Nested submodule evaluation retains resolver provenance for priority and
    # ownership, but the outer evaluation already validates the same authored
    # config at its full absolute option path. Re-checking a nested relative
    # path would lose that prefix and reject valid writes.
    enforcePackageAuthorization ? true,
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

      # `collectModules provenance authorization importRoot
      # propagateToImports mods` recursively
      # evaluates modules and stamps each result with resolver-controlled
      # provenance. Package imports retain their authenticated package owner;
      # host imports fall back to `@base`, preventing an operator module from
      # laundering an arbitrary import into tier 75. Module-authored
      # `_provenance` is rejected by `evalModule` before this point.
      visibleConfigFor = provenance: authorization:
        if !strings.hasPrefix "package:" provenance
        then finalConfig
        else let
          package = strings.removePrefix "package:" provenance;
          allowedRoots =
            [package]
            ++ authorization.owns
            ++ builtins.attrNames authorization.contributes;
          foreignPackageRoots =
            builtins.filter
            (root: !builtins.elem root allowedRoots)
            packageOwnedRoots;
        in
          finalConfig
          // builtins.listToAttrs (builtins.map
            (root:
              attrsets.nameValuePair root (throw
                "evalModules: package '${package}' reads undeclared package root '${root}'"))
            foreignPackageRoots);

      pathWithin = root: path: let
        rootString = builtins.toString root;
        pathString = builtins.toString path;
      in
        pathString == rootString || strings.hasPrefix "${rootString}/" pathString;

      confinedPackageImports = provenance: importRoot: imports:
        if importRoot == null
        then imports
        else
          builtins.map (
            imported:
              if !builtins.isPath imported
              then
                throw
                "evalModules: ${provenance} import is not a path literal; package imports must retain a path identity beneath its authenticated config root"
              else if
                builtins.any
                (component: component == "." || component == "..")
                (strings.splitString "/" (builtins.toString imported))
              then throw "evalModules: ${provenance} import contains a traversal component"
              else if !builtins.pathExists imported
              then throw "evalModules: ${provenance} import path '${builtins.toString imported}' does not exist"
              else if !pathWithin importRoot imported
              then
                throw
                "evalModules: ${provenance} import '${builtins.toString imported}' escapes authenticated config root '${builtins.toString importRoot}'"
              else imported
          )
          imports;

      collectModules = provenance: authorization: importRoot: moduleOutputs: propagateToImports: mods:
        builtins.concatLists (
          builtins.map (
            mod: let
              evaled =
                evalModule {
                  config = visibleConfigFor provenance authorization;
                  options = optionsTree;
                  pkgs =
                    if moduleOutputs == null
                    then pkgs
                    else {};
                  lib = moduleLib;
                  extraArgs =
                    extraArgs
                    // specialArgs
                    // {provenance = provenanceQueries;}
                    // (
                      if moduleOutputs == null
                      then {}
                      else {outputs = moduleOutputs;}
                    );
                }
                mod;
            in
              collectModules
              (
                if propagateToImports
                then provenance
                else if provenance == "@host" || provenance == "@host-import"
                then "@host-import"
                else "@base"
              )
              (
                if propagateToImports
                then authorization
                else null
              )
              (
                if propagateToImports
                then importRoot
                else null
              )
              (
                if propagateToImports
                then moduleOutputs
                else null
              )
              propagateToImports
              (confinedPackageImports provenance importRoot evaled.imports)
              ++ [
                (evaled
                  // {
                    _provenance = provenance;
                    _authorization = authorization;
                  })
              ]
          )
          mods
        );

      validAuthorization = auth:
        builtins.isAttrs auth
        && builtins.attrNames auth == ["contributes" "owns"]
        && builtins.isList auth.owns
        && builtins.all (root: builtins.isString root && builtins.match "[a-zA-Z0-9][a-zA-Z0-9_-]*" root != null) auth.owns
        && builtins.isAttrs auth.contributes
        && builtins.all (paths:
          builtins.isList paths
          && builtins.all (path:
            builtins.isString path
            && path != ""
            && builtins.match "[a-zA-Z0-9][a-zA-Z0-9_.-]*" path != null)
          paths)
        (builtins.attrValues auth.contributes);

      validPackageOutputs = outputs:
        builtins.isAttrs outputs
        && builtins.attrNames outputs == ["dependencies" "self"]
        && builtins.isString outputs.self
        && strings.hasPrefix "/nix/store/" outputs.self
        && builtins.isAttrs outputs.dependencies
        && builtins.all
        (path: builtins.isString path && strings.hasPrefix "/nix/store/" path)
        (builtins.attrValues outputs.dependencies);

      validatedPackageModules = builtins.map (record: let
        keys =
          if builtins.isAttrs record
          then builtins.attrNames record
          else [];
        configRoot = record.configRoot or null;
      in
        if
          !builtins.isAttrs record
          || !(keys
            == ["authorization" "module" "name"]
            || keys == ["authorization" "configRoot" "module" "name" "outputs"])
        then throw "evalModules: packageModules entries must contain authorization/module/name or the resolver-authenticated configRoot/outputs form"
        else if !builtins.isString record.name || builtins.match "[a-z0-9][a-z0-9._+-]*" record.name == null
        then throw "evalModules: invalid resolver-supplied package provenance name"
        else if !validAuthorization record.authorization
        then throw "evalModules: invalid resolver-supplied authorization for package '${record.name}'"
        else if
          configRoot
          != null
          && (!builtins.isPath configRoot
            || !builtins.isPath record.module
            || builtins.toString record.module != "${builtins.toString configRoot}/module.nix")
        then throw "evalModules: package '${record.name}' module is not module.nix beneath its authenticated configRoot"
        else if configRoot != null && !validPackageOutputs record.outputs
        then throw "evalModules: package '${record.name}' has invalid resolver-supplied outputs"
        else
          record
          // {
            inherit configRoot;
            outputs = record.outputs or null;
          })
      packageModules;

      packageOwnedRoots = lists.unique (builtins.concatLists (builtins.map
        (record: [record.name] ++ record.authorization.owns)
        validatedPackageModules));

      evaluatedPackageModules = builtins.concatLists (builtins.map (record:
        collectModules "package:${record.name}" record.authorization record.configRoot record.outputs true [record.module])
      validatedPackageModules);

      # Image modules carry `@base`; operator (host.nix) modules carry
      # `@host`. Appended last so their tier-75 defs also win any
      # `lastValue` tie at equal priority, matching "the operator overrides".
      evaluatedModules =
        collectModules "@base" null null null false ([internalModule] ++ modules)
        ++ evaluatedPackageModules
        ++ collectModules "@host" null null null false operatorModules;

      # Enumerate the concrete leaf paths actually authored by each package
      # module. The authenticated metadata is only an authorization claim; it
      # is never accepted as proof that the module stayed within that claim.
      # Imports retain the parent's resolver stamp and authorization, and a
      # forged `_file` is deliberately irrelevant.
      configLeafPaths = path: value:
        if isMkIf value
        then
          if value._condition
          then configLeafPaths path value._value
          else []
        else if isMkMerge value
        then builtins.concatLists (builtins.map (configLeafPaths path) value._values)
        else if isOverride value || isOrder value
        then configLeafPaths path value._value
        else if builtins.isAttrs value
        then
          builtins.concatLists (builtins.map
            (name: configLeafPaths (path ++ [name]) value.${name})
            (builtins.attrNames value))
        else [path];

      pathHasPrefix = prefix: path:
        builtins.length prefix
        <= builtins.length path
        && builtins.all
        (i: builtins.elemAt prefix i == builtins.elemAt path i)
        (builtins.genList (i: i) (builtins.length prefix));

      # Package modules may contribute only to these module-engine diagnostic
      # channels without claiming a package/shared root. They are typed and
      # consumed by the engine itself; they cannot materialize runtime state.
      packageEngineContributionRoots = ["assertions" "warnings"];

      authorizePackagePath = module: path: let
        package = strings.removePrefix "package:" module._provenance;
        root =
          if path == []
          then ""
          else builtins.head path;
        relative =
          if builtins.length path <= 1
          then []
          else
            builtins.genList
            (i: builtins.elemAt path (i + 1))
            (builtins.length path - 1);
        owns = [package] ++ module._authorization.owns;
        contributed = module._authorization.contributes.${root} or [];
        allowedContribution =
          builtins.any
          (declared: pathHasPrefix (strings.splitString "." declared) relative)
          contributed;
        foreignEnable =
          relative
          != []
          && builtins.elemAt relative (builtins.length relative - 1) == "enable";
        pathStr = builtins.concatStringsSep "." path;
      in
        if builtins.elem root packageEngineContributionRoots
        then true
        else if builtins.elem root owns
        then true
        else if foreignEnable
        then throw "evalModules: package '${package}' may not write foreign enable path '${pathStr}'"
        else if allowedContribution
        then true
        else throw "evalModules: package '${package}' writes unauthorized path '${pathStr}'";

      packageAuthorizationCheck =
        if !enforcePackageAuthorization
        then true
        else
          builtins.foldl'
          (checked: module:
            if !strings.hasPrefix "package:" (module._provenance or "")
            then checked
            else
              builtins.foldl'
              (inner: path: builtins.seq inner (authorizePackagePath module path))
              checked
              (configLeafPaths [] module.config))
          true
          evaluatedModules;

      authorizePackageDeclaration = decl: let
        package = strings.removePrefix "package:" decl.provenance;
        root =
          if decl.path == []
          then ""
          else builtins.head decl.path;
        owns = [package] ++ decl.authorization.owns;
      in
        if builtins.elem root owns
        then true
        else throw "evalModules: package '${package}' declares unauthorized foreign option '${builtins.concatStringsSep "." decl.path}'";

      packageDeclarationCheck =
        builtins.foldl'
        (checked: decl:
          if strings.hasPrefix "package:" (decl.provenance or "")
          then builtins.seq checked (authorizePackageDeclaration decl)
          else checked)
        true
        allOptionDecls;

      ownerForProvenance = provenance:
        if provenance == null || provenance == "@base"
        then "@base"
        else if provenance == "@host" || provenance == "@host-import"
        then "@host"
        else if strings.hasPrefix "package:" provenance
        then strings.removePrefix "package:" provenance
        else throw "evalModules: invalid engine provenance stamp '${provenance}'";

      defaultDependencyOwners = lists.unique (builtins.map
        (decl: ownerForProvenance decl.provenance)
        (builtins.filter
          (decl:
            (decl.provenance or "@base")
            != "@base"
            && !(isNoDefault decl.option.default))
          allOptionDecls));
      # Nix does not expose general config-read tracing. Preserve the one
      # dependency edge phase 4 can identify exactly: a value supplied by an
      # option declaration's synthetic default. A tiny, owner-specific store
      # context is invisible to the option type and serialized value, but is
      # retained when another definition directly projects that default into
      # an artifact. Ownership queries peel the marker back into its
      # authenticated declaration owner.
      defaultDependencyMarkers = builtins.listToAttrs (builtins.map (owner: let
        marker =
          builtins.toFile
          "aos-option-default-${builtins.substring 0 16 (builtins.hashString "sha256" owner)}"
          owner;
      in
        attrsets.nameValuePair
        (builtins.unsafeDiscardStringContext (builtins.toString marker))
        owner)
      defaultDependencyOwners);
      tagDefaultDependency = provenance: value: let
        owner = ownerForProvenance provenance;
        markerPaths = builtins.attrNames (attrsets.filterAttrs (_: candidate: candidate == owner) defaultDependencyMarkers);
        markerContext = builtins.listToAttrs (builtins.map
          (marker: attrsets.nameValuePair marker {path = true;})
          markerPaths);
        tag = current:
          if markerPaths == []
          then current
          else if builtins.isString current
          then builtins.appendContext current markerContext
          else if builtins.isList current
          then builtins.map tag current
          else if builtins.isAttrs current && !((current.type or null) == "derivation")
          then
            builtins.mapAttrs (name: child:
              if name == "_module"
              then child
              else tag child)
            current
          else current;
      in
        tag value;
      dependencyOwnersForValue = value: let
        collect = current:
          if builtins.isString current
          then
            builtins.map
            (marker: defaultDependencyMarkers.${marker})
            (builtins.filter
              (marker: builtins.hasAttr marker defaultDependencyMarkers)
              (builtins.attrNames (builtins.getContext current)))
          else if builtins.isList current
          then builtins.concatLists (builtins.map collect current)
          else if builtins.isAttrs current && !((current.type or null) == "derivation")
          then
            builtins.concatLists (builtins.map
              (name:
                if name == "_module"
                then []
                else collect current.${name})
              (builtins.attrNames current))
          else [];
      in
        lists.unique (collect value);

      peelOwnedDef = file: provenance: condition: priority: value:
        if isOverride value
        then peelOwnedDef file provenance condition value._priority value._value
        else if isMkIf value
        then peelOwnedDef file provenance (condition && value._condition) priority value._value
        else if isMkMerge value
        then
          builtins.concatLists (builtins.map
            (v: peelOwnedDef file provenance condition priority v)
            value._values)
        else if isOrder value
        then peelOwnedDef file provenance condition priority value._value
        else [{inherit file provenance condition priority value;}];

      chooseOwner = description: defs: let
        active = builtins.filter (d: d.condition) defs;
        minPriority =
          builtins.foldl'
          (acc: d:
            if d.priority < acc
            then d.priority
            else acc)
          9999
          active;
        winners = builtins.filter (d: d.priority == minPriority) active;
        owners = lists.unique (builtins.concatLists (builtins.map (d: let
          source = ownerForProvenance d.provenance;
          dependencies = dependencyOwnersForValue d.value;
        in
          if dependencies != [] && builtins.elem source ["@base" "@host"]
          then dependencies
          else [source] ++ dependencies)
        winners));
      in
        if owners == []
        then "@base"
        else if builtins.length owners == 1
        then builtins.head owners
        else throw "evalModules: artifact '${description}' has definitions from multiple owners: ${builtins.concatStringsSep ", " owners}";

      optionDefs = path: let
        key = builtins.concatStringsSep "." path;
      in
        if !(optionMap ? ${key})
        then throw "evalModules: provenance query names undeclared option '${key}'"
        else configForOption optionMap.${key};

      defBasePriority = d:
        if isOverride d.value
        then d.value._priority
        else if (d.provenance or "@base") == "@host"
        then 75
        else 100;

      # Resolver-only ownership queries passed to modules as the `provenance`
      # argument. These inspect engine-stamped definition records, never
      # `_file` or module-authored metadata.
      peelOrderValue = value:
        if isOrder value
        then peelOrderValue value._value
        else value;
      provenanceQueries = {
        # Resolver-authenticated package names in deterministic evaluation
        # order. Manifest renderers use this to discover package-private
        # projection options without granting packages a shared write root.
        packageNames = builtins.map (record: record.name) validatedPackageModules;

        ownerOfOption = path: let
          defs = builtins.concatLists (builtins.map (d:
            peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)
          (optionDefs path));
        in
          chooseOwner (builtins.concatStringsSep "." path) defs;

        ownerOfAttr = path: name: let
          defs = builtins.concatLists (builtins.map (d:
            builtins.concatLists (builtins.map (outer:
              if builtins.isAttrs outer.value && builtins.hasAttr name outer.value
              then peelOwnedDef outer.file outer.provenance outer.condition outer.priority outer.value.${name}
              else [])
            (peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)))
          (optionDefs path));
        in
          chooseOwner "${builtins.concatStringsSep "." path}.${name}" defs;

        # Returns every active authenticated owner whose definition contributes
        # to one dynamic attribute, independent of merge priority. Artifact
        # renderers use this to reject a unit or /etc leaf whose bytes depend
        # on more than one package: degraded projection cannot safely retain a
        # mixed-source artifact after dropping one of its dependencies.
        dependencyOwnersOfAttr = path: name: let
          defs = builtins.concatLists (builtins.map (d:
            builtins.concatLists (builtins.map (outer:
              if builtins.isAttrs outer.value && builtins.hasAttr name outer.value
              then peelOwnedDef outer.file outer.provenance outer.condition outer.priority outer.value.${name}
              else [])
            (peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)))
          (optionDefs path));
        in
          lists.unique (builtins.concatLists (builtins.map (d: let
            source = ownerForProvenance d.provenance;
            dependencies = dependencyOwnersForValue d.value;
          in
            if dependencies != [] && builtins.elem source ["@base" "@host"]
            then dependencies
            else [source] ++ dependencies)
          (builtins.filter (d: d.condition) defs)));

        # Resolver-stamped source records for collision checks. Values are not
        # exposed, so callers cannot accidentally build an alternate merge
        # path; file is diagnostic-only and owner remains engine-controlled.
        definitionsOfAttr = path: name: let
          defs = builtins.concatLists (builtins.map (d:
            builtins.concatLists (builtins.map (outer:
              if builtins.isAttrs outer.value && builtins.hasAttr name outer.value
              then peelOwnedDef outer.file outer.provenance outer.condition outer.priority outer.value.${name}
              else [])
            (peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)))
          (optionDefs path));
        in
          builtins.map (d: {
            inherit (d) file priority;
            owner = ownerForProvenance d.provenance;
          }) (builtins.filter (d: d.condition) defs);

        ownerOfListString = path: wanted: let
          defs = builtins.concatLists (builtins.map (d:
            builtins.map (value: value // {value = wanted;})
            (builtins.filter
              (value:
                builtins.isList value.value
                && builtins.any
                (item: builtins.toString (peelOrderValue item) == wanted)
                value.value)
              (peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)))
          (optionDefs path));
        in
          chooseOwner "${builtins.concatStringsSep "." path} item ${wanted}" defs;

        ownerOfListAttr = path: field: wanted: let
          defs = builtins.concatLists (builtins.map (d:
            builtins.map (value: value // {value = wanted;})
            (builtins.filter
              (value:
                builtins.isList value.value
                && builtins.any
                (item: let
                  normalized = peelOrderValue item;
                in
                  builtins.isAttrs normalized
                  && normalized ? ${field}
                  && normalized.${field} == wanted)
                value.value)
              (peelOwnedDef d.file (d.provenance or "@base") true (defBasePriority d) d.value)))
          (optionDefs path));
        in
          chooseOwner "${builtins.concatStringsSep "." path} item ${field}=${wanted}" defs;
      };

      # Nested options tree, built from mergedOptions and fed back to
      # module functions via evalModule's `options` arg. This is the
      # AOS equivalent of nixpkgs' `{ config, options, ... }: …` pattern.
      # The tree is lazy: module functions that don't take `options`
      # never trigger its construction; modules that take it and access
      # a specific leaf only force that one leaf.
      optionsTree = mkOptionsTree mergedOptions;

      # --- Phase 2: Collect all option declarations ---
      allOptionDecls = builtins.concatLists (
        builtins.map (m:
          collectOptions [] m.options m._file (m._provenance or "@base") (m._authorization or null))
        evaluatedModules
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
          builtins.map (m: collectDefsAtPath decl.path m.config m._file (m._provenance or null) (m._authorization or null)) evaluatedModules
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
                        if (d.provenance or null) == "@host"
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
            priorityFilteredDefs =
              if optType.mergeProvenanceByKey or false
              then unwrappedDefs
              else builtins.filter (d: d._priority == minPriority) unwrappedDefs;

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
                      provenance = decl.provenance or "@base";
                      authorization = decl.authorization or null;
                      value =
                        tagDefaultDependency
                        (decl.provenance or "@base")
                        decl.option.default;
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

      configWithFreeform = builtins.seq packageDeclarationCheck (builtins.seq packageAuthorizationCheck (
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
            ''
      ));
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
            inherit pkgs lib extraArgs specialArgs operatorModules packageModules enforcePackageAuthorization;
          }
          // builtins.removeAttrs args ["modules"]);

      # The declared contributable option surface, flattened to one record
      # per declared option path, carrying the stable type description and
      # `contributable` marker. This
      # is the data the publish-time options-only eval folds into the
      # registry inverted index (`option-path → {owner@version,
      # typeSig; contributable}`) so the resolver can hash the normative ABI
      # schema and authorize foreign writes
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
          typeSig = decl.option.type.description;
          contributable = decl.option.contributable or false;
          owner = ownerForProvenance (decl.provenance or "@base");
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
