# lib/attrsets.nix — Attribute set utility functions
#
# Functions for manipulating Nix attribute sets (dictionaries).
#

rec {
  # -- Accessors --

  # attrNames :: attrset -> [string]
  attrNames = builtins.attrNames;

  # attrValues :: attrset -> [a]
  attrValues = builtins.attrValues;

  # hasAttr :: string -> attrset -> bool
  hasAttr = builtins.hasAttr;

  # getAttr :: string -> attrset -> a
  getAttr = builtins.getAttr;

  # isAttrs :: a -> bool
  isAttrs = builtins.isAttrs;

  # -- Construction --

  # nameValuePair :: string -> a -> { name :: string; value :: a; }
  # Create a name-value pair suitable for listToAttrs.
  nameValuePair = name: value: { inherit name value; };

  # listToAttrs :: [{ name :: string; value :: a; }] -> attrset
  listToAttrs = builtins.listToAttrs;

  # genAttrs :: [string] -> (string -> a) -> attrset
  # Generate an attrset from a list of names and a function.
  # genAttrs ["a" "b"] (n: n + "!") == { a = "a!"; b = "b!"; }
  genAttrs =
    names: f:
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = f name;
      }) names
    );

  # optionalAttrs :: bool -> attrset -> attrset
  # Return the attrset if condition is true, otherwise empty.
  optionalAttrs = cond: attrs: if cond then attrs else { };

  # -- Mapping --

  # mapAttrs :: (string -> a -> b) -> attrset -> attrset
  mapAttrs = builtins.mapAttrs;

  # mapAttrsToList :: (string -> a -> b) -> attrset -> [b]
  # Map over an attrset and collect results into a list.
  mapAttrsToList = f: attrs: builtins.map (name: f name attrs.${name}) (builtins.attrNames attrs);

  # mapAttrs' :: (string -> a -> { name :: string; value :: b; }) -> attrset -> attrset
  # Map over attrs, allowing renaming of keys.
  mapAttrs' = f: attrs: builtins.listToAttrs (mapAttrsToList f attrs);

  # mapAttrsRecursive :: ([string] -> a -> b) -> attrset -> attrset
  # Recursively map over leaf values in a nested attrset.
  # The function receives the path (list of attribute names) and the leaf value.
  mapAttrsRecursive =
    f: attrs:
    let
      go =
        path: set:
        builtins.mapAttrs (
          name: value:
          let
            newPath = path ++ [ name ];
          in
          if builtins.isAttrs value && !(value ? _type) then go newPath value else f newPath value
        ) set;
    in
    go [ ] attrs;

  # mapAttrsRecursiveCond :: (attrset -> bool) -> ([string] -> a -> b) -> attrset -> attrset
  # Like mapAttrsRecursive but only recurse into attrsets satisfying a predicate.
  mapAttrsRecursiveCond =
    cond: f: attrs:
    let
      go =
        path: set:
        builtins.mapAttrs (
          name: value:
          let
            newPath = path ++ [ name ];
          in
          if builtins.isAttrs value && cond value then go newPath value else f newPath value
        ) set;
    in
    go [ ] attrs;

  # -- Filtering --

  # filterAttrs :: (string -> a -> bool) -> attrset -> attrset
  # Keep only attributes satisfying the predicate.
  filterAttrs =
    pred: attrs:
    builtins.listToAttrs (
      builtins.filter (pair: pred pair.name pair.value) (mapAttrsToList nameValuePair attrs)
    );

  # filterAttrsRecursive :: (string -> a -> bool) -> attrset -> attrset
  # Recursively filter attributes.
  filterAttrsRecursive =
    pred: attrs:
    builtins.listToAttrs (
      builtins.concatLists (
        mapAttrsToList (
          name: value:
          if !pred name value then
            [ ]
          else
            [
              {
                inherit name;
                value = if builtins.isAttrs value then filterAttrsRecursive pred value else value;
              }
            ]
        ) attrs
      )
    );

  # -- Folding --

  # foldAttrs :: (a -> b -> b) -> b -> [attrset] -> attrset
  # Fold a list of attrsets, combining values for the same key.
  foldAttrs =
    f: init: listOfAttrs:
    let
      allNames = builtins.concatLists (builtins.map builtins.attrNames listOfAttrs);
      uniqueNames =
        let
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] allNames;
    in
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = builtins.foldl' (
          acc: attrs: if builtins.hasAttr name attrs then f attrs.${name} acc else acc
        ) init listOfAttrs;
      }) uniqueNames
    );

  # foldlAttrs :: (b -> string -> a -> b) -> b -> attrset -> b
  # Left fold over an attrset's key-value pairs.
  foldlAttrs =
    f: init: attrs:
    builtins.foldl' (acc: name: f acc name attrs.${name}) init (builtins.attrNames attrs);

  # -- Merging --

  # recursiveUpdate :: attrset -> attrset -> attrset
  # Deep merge two attrsets. Values in the second override the first.
  # Recursion occurs only when both sides are attrsets (and not derivations).
  recursiveUpdate =
    lhs: rhs:
    let
      lhsNames = builtins.attrNames lhs;
      rhsNames = builtins.attrNames rhs;
      allNames =
        let
          combined = lhsNames ++ rhsNames;
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] combined;
    in
    builtins.listToAttrs (
      builtins.map (
        name:
        let
          lhsHas = builtins.hasAttr name lhs;
          rhsHas = builtins.hasAttr name rhs;
          lhsVal = lhs.${name} or null;
          rhsVal = rhs.${name} or null;
        in
        {
          inherit name;
          value =
            if lhsHas && rhsHas then
              if
                builtins.isAttrs lhsVal && builtins.isAttrs rhsVal && !(lhsVal ? outPath) && !(rhsVal ? outPath)
              then
                recursiveUpdate lhsVal rhsVal
              else
                rhsVal
            else if rhsHas then
              rhsVal
            else
              lhsVal;
        }
      ) allNames
    );

  # recursiveUpdateUntil :: ([string] -> attrset -> attrset -> bool) -> attrset -> attrset -> attrset
  # Like recursiveUpdate but stop recursing when the predicate returns true.
  recursiveUpdateUntil =
    pred: lhs: rhs:
    let
      go =
        path: l: r:
        let
          lNames = builtins.attrNames l;
          rNames = builtins.attrNames r;
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
          builtins.map (
            name:
            let
              lHas = builtins.hasAttr name l;
              rHas = builtins.hasAttr name r;
              lVal = l.${name} or null;
              rVal = r.${name} or null;
              newPath = path ++ [ name ];
            in
            {
              inherit name;
              value =
                if lHas && rHas then
                  if builtins.isAttrs lVal && builtins.isAttrs rVal && !pred newPath lVal rVal then
                    go newPath lVal rVal
                  else
                    rVal
                else if rHas then
                  rVal
                else
                  lVal;
            }
          ) allNames
        );
    in
    go [ ] lhs rhs;

  # -- Extraction --

  # catAttrs :: string -> [attrset] -> [a]
  # Collect attribute values from a list of attrsets (skipping those without the key).
  catAttrs = builtins.catAttrs;

  # collect :: (a -> bool) -> attrset -> [a]
  # Recursively collect leaf values satisfying a predicate from a nested attrset.
  collect =
    pred: attrs:
    if pred attrs then
      [ attrs ]
    else if builtins.isAttrs attrs then
      builtins.concatLists (builtins.map (name: collect pred attrs.${name}) (builtins.attrNames attrs))
    else
      [ ];

  # collectLeaves :: attrset -> [a]
  # Recursively collect all leaf (non-attrset) values from a nested attrset.
  collectLeaves =
    attrs:
    if !builtins.isAttrs attrs then
      [ attrs ]
    else
      builtins.concatLists (builtins.map (name: collectLeaves attrs.${name}) (builtins.attrNames attrs));

  # -- Zipping --

  # zipAttrs :: [attrset] -> attrset
  # Merge a list of attrsets, collecting values for duplicate keys into lists.
  # zipAttrs [{ a = 1; } { a = 2; b = 3; }] == { a = [1 2]; b = [3]; }
  zipAttrs =
    listOfAttrs:
    let
      allNames = builtins.concatLists (builtins.map builtins.attrNames listOfAttrs);
      uniqueNames =
        let
          go =
            acc: remaining:
            if remaining == [ ] then
              acc
            else
              let
                h = builtins.elemAt remaining 0;
                t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
              in
              if builtins.any (x: x == h) acc then go acc t else go (acc ++ [ h ]) t;
        in
        go [ ] allNames;
    in
    builtins.listToAttrs (
      builtins.map (name: {
        inherit name;
        value = builtins.concatLists (
          builtins.map (attrs: if builtins.hasAttr name attrs then [ attrs.${name} ] else [ ]) listOfAttrs
        );
      }) uniqueNames
    );

  # zipAttrsWith :: (string -> [a] -> b) -> [attrset] -> attrset
  # Like zipAttrs but apply a combining function to the collected values.
  zipAttrsWith = f: listOfAttrs: builtins.mapAttrs f (zipAttrs listOfAttrs);

  # -- Lookup --

  # attrByPath :: [string] -> a -> attrset -> a
  # Look up a nested attribute by a path of key names, with a default.
  attrByPath =
    path: default: attrs:
    let
      go =
        remaining: current:
        if remaining == [ ] then
          current
        else
          let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
          if builtins.isAttrs current && builtins.hasAttr h current then go t current.${h} else default;
    in
    go path attrs;

  # hasAttrByPath :: [string] -> attrset -> bool
  # Test whether a nested attribute path exists.
  hasAttrByPath =
    path: attrs:
    let
      go =
        remaining: current:
        if remaining == [ ] then
          true
        else
          let
            h = builtins.elemAt remaining 0;
            t = builtins.genList (i: builtins.elemAt remaining (i + 1)) (builtins.length remaining - 1);
          in
          if builtins.isAttrs current && builtins.hasAttr h current then go t current.${h} else false;
    in
    go path attrs;

  # setAttrByPath :: [string] -> a -> attrset
  # Create a nested attrset with a single leaf value at the given path.
  # setAttrByPath ["a" "b" "c"] 42 == { a = { b = { c = 42; }; }; }
  setAttrByPath =
    path: value:
    let
      len = builtins.length path;
      go = i: if i >= len then value else { ${builtins.elemAt path i} = go (i + 1); };
    in
    if len == 0 then value else go 0;

  # getOutput :: string -> derivation -> derivation
  # Get a specific output of a multi-output derivation.
  getOutput = output: drv: if drv ? outputSpecified && drv ? ${output} then drv.${output} else drv;

  # -- Conversion --

  # attrsToList :: attrset -> [{ name :: string; value :: a; }]
  attrsToList =
    attrs:
    builtins.map (name: {
      inherit name;
      value = attrs.${name};
    }) (builtins.attrNames attrs);

  # removeAttrs :: attrset -> [string] -> attrset
  removeAttrs = builtins.removeAttrs;

  # intersectAttrs :: attrset -> attrset -> attrset
  intersectAttrs = builtins.intersectAttrs;

  # overrideExisting :: attrset -> attrset -> attrset
  # Update only attributes that already exist in the original.
  overrideExisting = old: new: builtins.mapAttrs (name: value: new.${name} or value) old;
}
