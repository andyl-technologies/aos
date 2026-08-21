##! lib/build/freeze-pkgs.nix — frozen `pkgs` for on-host configuration evaluation
##!
##! The stage-2 on-host evaluator must compute the config manifest WITHOUT
##! traversing the from-source `pkgs` build graph: under the eval sandbox
##! (`restrict-eval`, no IFD) forcing any from-source derivation pulls in the
##! bootstrap chain's eval-time fetches, which the sandbox forbids. Store paths
##! selected by host configuration are therefore computed at image-build time
##! without retaining packages that the evaluated image does not select.
##!
##! `freezePkgs` turns a live `pkgs` set into a *frozen* one: every derivation is
##! replaced by a plain attrset whose `outPath` (and per-output paths) are
##! reversibly encoded store-path strings, with `__toString` so `${pkgs.foo}` and
##! `${pkgs.foo.lib}` interpolate the path exactly as before — but with no
##! derivation behind them, so the eval never touches the build graph. Literal
##! store paths cannot appear in the serialized form because Nix scans output
##! bytes for them and would retain every package in the image closure.
##!
##! Two halves:
##!   - `freezeToJSON pkgs` — run at stage-1 (base-lib build): forces the
##!     store paths once and serialises `name → { outPath; outputs; }`.
##!   - `frozenFromJSON json` — run at stage-2: rebuilds the string-coercible
##!     frozen set from that JSON; touches no derivation.
##!
##! Frozen packages are data, not functions: `pkgs.foo.override`,
##! `pkgs.writeText`, `pkgs.runCommand`, etc. are NOT available. Config modules
##! that need to *build* something at eval time are by definition not eval-only
##! and must instead carry rendered text/store-path strings (the F2-A
##! render/assemble split). A frozen access to a missing builder surfaces as a
##! clear `attribute 'X' missing` rather than a build-graph escape.
{lib}: let
  isDrv = v: builtins.isAttrs v && (v.type or null) == "derivation";

  # Discard string context so the path is a plain string with no derivation
  # dependency riding along into the frozen value.
  pathString = p: builtins.unsafeDiscardStringContext (toString p);
  reverse = value: let
    length = builtins.stringLength value;
  in
    lib.concatStrings (builtins.genList (
        index: builtins.substring (length - index - 1) 1 value
      )
      length);
  encodePath = p: let
    value = pathString p;
  in
    if lib.hasPrefix "/nix/store/" value
    then "@nix-store@/${reverse (lib.removePrefix "/nix/store/" value)}"
    else throw "freeze-pkgs: package output is not a Nix store path: ${value}";
  decodePath = value:
    if lib.hasPrefix "@nix-store@/" value
    then "/nix/store/${reverse (lib.removePrefix "@nix-store@/" value)}"
    else throw "freeze-pkgs: invalid encoded store path";

  # Freeze a single derivation to a JSON-safe record. NOTE: the key must NOT be
  # `outPath` — `builtins.toJSON` coerces any attrset carrying an `outPath` field
  # to that path string (the derivation coercion), collapsing the record. Use
  # `path` + an `outPaths` map; `frozenFromJSON` reconstitutes `outPath` from it.
  freezeDrv = name: drv: let
    outputs = drv.outputs or ["out"];
    outPaths = builtins.listToAttrs (builtins.map (o: {
        name = o;
        value = encodePath (lib.getOutput o drv).outPath;
      })
      outputs);
  in {
    path = encodePath drv.outPath;
    outputs = outputs;
    outPaths = outPaths;
    # Package-provided systemd units must remain enumerable during on-host
    # evaluation without reading the package output (which would be IFD when
    # the same expression is evaluated during image construction).  Package
    # recipes therefore publish a relative-path inventory as pure passthru
    # data.  Preserve that one standardized metadata field in the frozen set.
    systemdUnitInventory =
      drv.systemdUnitInventory
      or (drv.passthru.systemdUnitInventory or {});
    inherit name;
  };
in {
  ## Stage-1: serialise the frozen form of `pkgs` (top-level derivations only).
  ## Forces the store paths; run inside the base-lib builder.
  freezeToJSON = pkgs:
    builtins.toJSON (lib.filterAttrs (_: v: v != null) (
      builtins.mapAttrs (
        name: v:
          if isDrv v
          then freezeDrv name v
          else null
      )
      pkgs
    ));

  ## Stage-2: rebuild the string-coercible frozen `pkgs` from the JSON. The
  ## resulting `pkgs.foo` interpolates to its `outPath`; `pkgs.foo.<output>`
  ## interpolates to that output's path. No derivation is forced.
  frozenFromJSON = json: let
    # `builtins.readFile` of a store path (the base-lib `frozen-pkgs.json`)
    # returns a string carrying that path as string context, and
    # `builtins.fromJSON` rejects context-bearing strings ("the string '…' is
    # not allowed to refer to a store path"). The context is irrelevant here —
    # we only parse the bytes — so discard it.
    parsed = builtins.fromJSON (builtins.unsafeDiscardStringContext json);
    mkOutput = nm: p: {
      type = "derivation";
      name = nm;
      outPath = p;
      __toString = _: p;
    };
    mkFrozen = name: e: let
      outputs = e.outputs or ["out"];
    in let
      path = decodePath e.path;
    in
      {
        type = "derivation";
        name = e.name or name;
        outPath = path;
        outputName = builtins.head outputs;
        systemdUnitInventory = e.systemdUnitInventory or {};
        __toString = _: path;
      }
      // builtins.listToAttrs (builtins.map (o: {
          name = o;
          value = mkOutput "${name}-${o}" (decodePath ((e.outPaths or {}).${o} or e.path));
        })
        outputs);
  in
    builtins.mapAttrs mkFrozen parsed;
}
