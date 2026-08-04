# SPDX-License-Identifier: MIT
#
# Ported from nixpkgs for use in AOS.
#   Upstream path: nixos/lib/systemd-lib.nix
#   Upstream rev:  6c9a78c09ff4d6c21d0319114873508a6ec01655
#
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.
#
# AOS adaptations (summary, spec §5):
#   - Top-level signature takes only `{ lib, pkgs }`. The upstream
#     `{ config, lib, pkgs, utils }` binding is split: `cfg.package` /
#     `cfg.packages` / `cfg.globalEnvironment` are handled at the module
#     seam in modules/systemd/system.nix (see spec §4.2), `utils` is
#     inlined (only `escapeSystemdPath` was needed, ported below).
#   - `makeJobScript` no longer returns a bare `writeShellScriptBin` path.
#     On-host evaluation reroutes it to a pure data record carrying the job
#     script's TEXT (for `manifest.jobScripts`) plus a build-side
#     derivation that materializes the script at an `aos-job-scripts/<key>`
#     path; the `Exec*=` directive now points there. See `makeJobScript`
#     below. (The dropped `writeShellApplication`/shellcheck branch — AOS
#     has no Haskell toolchain, spec §5.4 — stays dropped.)
#   - `generateUnits` now returns pure unit records. `unitsToEtc` flattens
#     those records into the manifest layout and `materializeUnits` is the
#     only build-side derivation seam. Package/upstream discovery consumes a
#     stage-1-authored `systemdUnitInventory` instead of reading outputs (IFD).
#   - The `X-*` switch-to-configuration emissions were originally dropped
#     here. The live in-place `apm upgrade --system` path
#     (2026-05-27_apm_system_upgrade_refactor_v2 §6.4) restores them: the
#     `unitConfig` mixin emits `X-RestartIfChanged`, `X-ReloadIfChanged`,
#     `X-StopOnRemoval`, `X-StopOnReconfiguration`, `X-OnlyManualStart`,
#     `X-NotSocketActivated`, and `X-Reload-Triggers` into `[Unit]`, and
#     the `serviceConfig` mixin adds the service-only `X-StopIfChanged`.
#     Unlike upstream — which splits these between `[Unit]` and `[Service]`
#     and uses `pkgs.writeText` for the trigger lists — AOS renders the
#     whole contract into `[Unit]` and uses a plain space-joined path list
#     for `X-Reload-Triggers`. `X-Restart-Triggers` stays dropped
#     (`restartTriggers` is out of scope). Every emission is gated on a
#     non-default value, so default-config units render unchanged.
#   - `serviceConfig`'s `nixosConfig = config` closure is removed along
#     with `enableStrictShellChecks` (spec §5.4/§5.8). `serviceConfig`
#     is now a pure `{ name, lib, config, ... }:` submodule fragment.
#   - `serviceToUnit` no longer reads `cfg.globalEnvironment`. The
#     globalEnvironment merge is applied at the module seam in
#     modules/systemd/system.nix before definitions reach this library
#     (spec §4.2).
#   - `stage2ServiceConfig` uses `pkgs.grep` / `pkgs.sed` / `pkgs.systemd`
#     (not `pkgs.gnugrep` / `pkgs.gnused` / `cfg.package`), matching
#     AOS's package naming. See `pkgs/default.nix` §321-325.
#   - `definitions` (networkd `.conf` file generator) is dropped; typed
#     networkd is out of scope (spec §11.1).
{
  lib,
  pkgs,
}: let
  inherit
    (lib)
    all
    attrByPath
    attrNames
    concatLists
    concatMap
    concatMapStrings
    concatStrings
    concatStringsSep
    const
    elem
    filter
    filterAttrs
    flatten
    flip
    hasPrefix
    head
    isList
    isString
    length
    makeBinPath
    makeSearchPath
    mapAttrs
    mapAttrsToList
    mapNullable
    match
    mkAfter
    mkIf
    optional
    optionalAttrs
    optionalString
    pipe
    range
    replaceStrings
    reverseList
    splitString
    stringLength
    tail
    types
    ;

  # Shims for nixpkgs-style library names that AOS exposes only as
  # `builtins.*` or under a different name.
  elemAt = builtins.elemAt;
  isInt = builtins.isInt;
  isFloat = builtins.isFloat;
  trace = builtins.trace;
  isPath = builtins.isPath;
  toIntBase10 = lib.toInt;

  # nixpkgs uses `lib.strings.toJSON`; AOS has only `builtins.toJSON`,
  # which produces the same output for the subset of values we care about
  # (strings, numbers, booleans, lists of the same).
  toJSON = builtins.toJSON;

  # ------------------------------------------------------------------
  # escapeSystemdPath — ported from nixos/lib/utils.nix (inlined here
  # so lib.nix stays a pure library without pulling in a utils module).
  # ------------------------------------------------------------------
  #
  # The escaping rules are from systemd.unit(5): slashes become dashes;
  # any non-alphanumeric / `:` / `_` / `.` character becomes a C-style
  # `\xNN` escape; a leading `.` also gets escaped. Absolute paths have
  # leading, trailing, and duplicate slashes stripped before escaping.
  stringToCharacters = s: let
    n = stringLength s;
    go = i:
      if i >= n
      then []
      else [(builtins.substring i 1 s)] ++ go (i + 1);
  in
    go 0;

  # Port of nixpkgs' `lib.strings.escapeC`: for every character in
  # `charsToEscape`, replace it with `\xNN` (lowercase hex) in `s`.
  # We only need the subset of ASCII that systemd path escaping touches,
  # so a small lookup table is enough. Values are lowercase two-digit hex.
  escapeC = charsToEscape: s: let
    hexTable = {
      " " = "20";
      "!" = "21";
      "\"" = "22";
      "#" = "23";
      "$" = "24";
      "%" = "25";
      "&" = "26";
      "'" = "27";
      "(" = "28";
      ")" = "29";
      "*" = "2a";
      "+" = "2b";
      "," = "2c";
      ";" = "3b";
      "<" = "3c";
      "=" = "3d";
      ">" = "3e";
      "@" = "40";
      "[" = "5b";
      "\\" = "5c";
      "]" = "5d";
      "^" = "5e";
      "`" = "60";
      "{" = "7b";
      "|" = "7c";
      "}" = "7d";
      "~" = "7e";
      "-" = "2d";
      "." = "2e";
    };
    escapeOne = ch:
      if elem ch charsToEscape && hexTable ? ${ch}
      then "\\x${hexTable.${ch}}"
      else ch;
  in
    concatStrings (builtins.map escapeOne (stringToCharacters s));

  escapeSystemdPath = s: let
    # Simple normalisation: strip trailing slashes, leading slashes for
    # absolute paths. AOS's current systemd.mounts consumers don't use
    # pathological paths with duplicate internal slashes, so collapsing
    # those is out of scope for this port.
    trim = str: let
      noTrailing =
        if lib.hasSuffix "/" str && stringLength str > 1
        then lib.removeSuffix "/" str
        else str;
      noLeading =
        if hasPrefix "/" noTrailing
        then lib.removePrefix "/" noTrailing
        else noTrailing;
    in
      noLeading;
    normalized =
      if s == "/"
      then "/"
      else trim s;
    # Leading `.` also gets escaped, per systemd.unit(5).
    escaped = escapeC (stringToCharacters " !\"#$%&'()*+,;<=>=@[\\]^`{|}~-") (
      if hasPrefix "." normalized
      then "\\x2e" + builtins.substring 1 (stringLength normalized - 1) normalized
      else normalized
    );
  in
    replaceStrings ["/"] ["-"] escaped;
in rec {
  shellEscape = s: replaceStrings ["\\"] ["\\\\"] s;

  mkPathSafeName = replaceStrings ["/" "@" ":" "\\" "[" "]"] ["-" "-" "-" "-" "" ""];

  # A type for options that take a unit name.
  unitNameType = types.strMatching "[a-zA-Z0-9@%:_.\\-]+[.](service|socket|device|mount|automount|swap|target|path|timer|scope|slice)";

  # makeUnit — build a single unit as its own derivation, so upstream
  # machinery (`generateUnits`, `systemd.packages` drop-ins) can symlink
  # it into the final `/etc/systemd/system/` tree.
  #
  # When `unit.enable == false`, the unit is rendered as a symlink to
  # /dev/null — the systemd idiom for "mask this unit", and what lets
  # AOS modules disable an upstream unit without deleting its file.
  makeUnit = name: unit:
    if unit.enable
    then let
      # `unit.text` carries `#aos-jobscript:<key>#`
      # placeholders (so the eval-only manifest can render the body without
      # forcing any job-script derivation). Restore the build-side store paths
      # here, on the *build* side, so the materialized unit file boots gen-0.
      # `replaceStrings` forces each `j.path` (hence its `writeTextFile` drv) —
      # legitimate: this derivation is toplevel-only and is never forced by the
      # on-host eval-only manifest path. Non-service units carry no job scripts
      # (`jobScripts` defaults to `[]`), so this is the identity there. The
      # result is byte-for-byte identical to embedding `j.path` directly.
      jobScripts = unit.jobScripts or [];
      resolvedText =
        if unit.text == null
        then ""
        else
          builtins.replaceStrings
          (builtins.map (j: j.placeholder) jobScripts)
          (builtins.map (j: j.path) jobScripts)
          unit.text;
    in
      pkgs.runCommand "unit-${mkPathSafeName name}" {
        preferLocalBuild = true;
        allowSubstitutes = false;
        # unit.text can be null for disabled units; passAsFile with a null
        # variable is a no-op in Nix, so guard with optionalString to avoid
        # the mv call failing on a missing $textPath.
        text = resolvedText;
        passAsFile = ["text"];
      } ''
        name=${shellEscape name}
        mkdir -p "$out/$(dirname -- "$name")"
        mv "$textPath" "$out/$name"
      ''
    else
      pkgs.runCommand "unit-${mkPathSafeName name}-disabled" {
        preferLocalBuild = true;
        allowSubstitutes = false;
      } ''
        name=${shellEscape name}
        mkdir -p "$out/$(dirname "$name")"
        ln -s /dev/null "$out/$name"
      '';

  boolValues = [
    true
    false
    "yes"
    "no"
  ];

  digits = builtins.map builtins.toString (range 0 9);

  isByteFormat = s: let
    l = reverseList (stringToCharacters s);
    suffix = head l;
    nums = tail l;
  in
    builtins.isInt s
    || (
      elem suffix (
        [
          "K"
          "M"
          "G"
          "T"
        ]
        ++ digits
      )
      && all (num: elem num digits) nums
    );

  assertByteFormat = name: group: attr:
    optional (
      attr ? ${name} && !isByteFormat attr.${name}
    ) "Systemd ${group} field `${name}' must be in byte format [0-9]+[KMGT].";

  toIntBaseDetected = value:
    assert (match "[0-9]+|0x[0-9a-fA-F]+" value) != null;
      (builtins.fromTOML "v=${value}").v;

  hexChars = stringToCharacters "0123456789abcdefABCDEF";

  isMacAddress = s:
    stringLength s
    == 17
    && flip all (splitString ":" s) (bytes: all (byte: elem byte hexChars) (stringToCharacters bytes));

  assertMacAddress = name: group: attr:
    optional (
      attr ? ${name} && !isMacAddress attr.${name}
    ) "Systemd ${group} field `${name}' must be a valid MAC address.";

  assertNetdevMacAddress = name: group: attr:
    optional (
      attr ? ${name} && (!isMacAddress attr.${name} && attr.${name} != "none")
    ) "Systemd ${group} field `${name}` must be a valid MAC address or the special value `none`.";

  isNumberOrRangeOf = check: v:
    if isInt v
    then check v
    else let
      parts = splitString "-" v;
      lower = toIntBase10 (head parts);
      upper =
        if tail parts != []
        then toIntBase10 (head (tail parts))
        else lower;
    in
      length parts <= 2 && lower <= upper && check lower && check upper;
  isPort = i: i >= 0 && i <= 65535;
  isPortOrPortRange = isNumberOrRangeOf isPort;

  assertPort = name: group: attr:
    optional (
      attr ? ${name} && !isPort attr.${name}
    ) "Error on the systemd ${group} field `${name}': ${attr.name} is not a valid port number.";

  assertPortOrPortRange = name: group: attr:
    optional (attr ? ${name} && !isPortOrPortRange attr.${name})
    "Error on the systemd ${group} field `${name}': ${attr.name} is not a valid port number or range of port numbers.";

  assertValueOneOf = name: values: group: attr:
    optional (
      attr ? ${name} && !elem attr.${name} values
    ) "Systemd ${group} field `${name}' cannot have value `${builtins.toString attr.${name}}'.";

  assertValuesSomeOfOr = name: values: default: group: attr:
    optional (
      attr
      ? ${name}
      && !(all (x: elem x values) (splitString " " attr.${name}) || attr.${name} == default)
    ) "Systemd ${group} field `${name}' cannot have value `${builtins.toString attr.${name}}'.";

  assertHasField = name: group: attr:
    optional (!(attr ? ${name})) "Systemd ${group} field `${name}' must exist.";

  assertRange = name: min: max: group: attr:
    optional (
      attr ? ${name} && !(min <= attr.${name} && max >= attr.${name})
    ) "Systemd ${group} field `${name}' is outside the range [${builtins.toString min},${builtins.toString max}]";

  assertRangeOrOneOf = name: min: max: values: group: attr:
    optional
    (
      attr
      ? ${name}
      && !(
        ((isInt attr.${name} || isFloat attr.${name}) && min <= attr.${name} && max >= attr.${name})
        || elem attr.${name} values
      )
    )
    "Systemd ${group} field `${name}' is not a value in range [${builtins.toString min},${builtins.toString max}], or one of ${builtins.toString values}";

  assertMinimum = name: min: group: attr:
    optional (
      attr ? ${name} && attr.${name} < min
    ) "Systemd ${group} field `${name}' must be greater than or equal to ${builtins.toString min}";

  assertOnlyFields = fields: group: attr: let
    badFields = filter (name: !elem name fields) (attrNames attr);
  in
    optional (
      badFields != []
    ) "Systemd ${group} has extra fields [${concatStringsSep " " badFields}].";

  assertInt = name: group: attr:
    optional (
      attr ? ${name} && !isInt attr.${name}
    ) "Systemd ${group} field `${name}' is not an integer";

  assertRemoved = name: see: group: attr:
    optional (attr ? ${name}) "Systemd ${group} field `${name}' has been removed. See ${see}";

  assertKeyIsSystemdCredential = name: group: attr:
    optional (
      attr ? ${name} && !(hasPrefix "@" attr.${name})
    ) "Systemd ${group} field `${name}' is not a systemd credential";

  checkUnitConfig = group: checks: attrs: let
    # Top-level type is attrsOf unitOption; unwrap override / if markers
    # before inspecting the values.
    defs =
      mapAttrs (const (
        v:
          if v._type or "" == "override"
          then v.content
          else if v._type or "" == "if"
          then v.content
          else v
      ))
      attrs;
    errors = concatMap (c: c group defs) checks;
  in
    if errors == []
    then true
    else trace (concatStringsSep "\n" errors) false;

  # Minimal pretty-printer used only by `checkUnitConfigWithLegacyKey`'s
  # error message. Nixpkgs uses `lib.generators.toPretty` for a fuller
  # rendering; AOS doesn't have that helper, so we fall back to printing
  # the keys and string values at one level of depth. Enough to debug a
  # misplaced `networkConfig`-style legacy key collision without porting
  # the full pretty-printer.
  _shallowDump = attrs:
    if builtins.isAttrs attrs
    then
      "{ "
      + concatStringsSep "; " (
        mapAttrsToList (
          n: v: "${n} = ${
            if builtins.isString v
            then "\"${v}\""
            else if builtins.isAttrs v
            then "{ ... }"
            else builtins.toString v
          }"
        )
        attrs
      )
      + "; }"
    else builtins.toString attrs;

  checkUnitConfigWithLegacyKey = legacyKey: group: checks: attrs: let
    dump = _shallowDump attrs;
    attrs' =
      if legacyKey == null
      then attrs
      else if !(attrs ? ${legacyKey})
      then attrs
      else if builtins.removeAttrs attrs [legacyKey] == {}
      then attrs.${legacyKey}
      else
        throw ''
          The declaration

          ${dump}

          must not mix unit options with the legacy key '${legacyKey}'.

          This can be fixed by moving all settings from within ${legacyKey}
          one level up.
        '';
  in
    checkUnitConfig group checks attrs';

  toOption = x:
    if x == true
    then "true"
    else if x == false
    then "false"
    else builtins.toString x;

  attrsToSection = as:
    concatStrings (
      concatLists (
        mapAttrsToList (
          name: value:
            builtins.map (x: ''
              ${name}=${toOption x}
            '') (
              if isList value
              then value
              else [value]
            )
        )
        as
      )
    );

  settingsToSections = settings:
    concatStringsSep "\n" (
      mapAttrsToList (section_name: section_attrs: ''
        [${section_name}]
        ${attrsToSection section_attrs}
      '')
      settings
    );

  # generateUnits — render systemd units as pure data.
  #
  # Authored records remain keyed by full unit name; inventory leaves use an
  # internal slash-bearing key (not a valid unit name) while retaining their
  # final path in `name`.
  # Every value is JSON-safe pure data and deliberately omits the legacy
  # `unit` derivation and derivation-bearing job-script fields.
  #
  # Package outputs cannot be enumerated during pure evaluation. Packages that
  # provide unit files therefore carry a `systemdUnitInventory.<type>` list of
  # paths relative to their output. `freeze-pkgs.nix` preserves this metadata,
  # so image-build and on-host evaluation consume the same pure inventory.
  generateUnits = {
    allowCollisions ? true,
    type,
    units,
    upstreamUnits ? [],
    upstreamWants ? [],
    packages ? [],
    package ? null,
    packageOwners ? {},
  }: let
    typeDir =
      {
        system = "system";
        initrd = "system";
        user = "user";
        nspawn = "nspawn";
      }
      .${
        type
      };
    normalRoots = [
      "etc/systemd/${typeDir}/"
      "lib/systemd/${typeDir}/"
    ];
    upstreamRoot = "example/systemd/${typeDir}/";
    allRoots = normalRoots ++ [upstreamRoot];

    inventoryOf = pkg: let
      inventory =
        pkg.systemdUnitInventory
        or (pkg.passthru.systemdUnitInventory or null);
    in
      if inventory == null || !(inventory ? ${type})
      then throw "generateUnits: package ${builtins.toString pkg} has no systemdUnitInventory.${type}"
      else inventory.${type};

    normalizeInventoryEntry = pkg: owner: raw: let
      item =
        if isString raw
        then {path = raw;}
        else if builtins.isAttrs raw
        then raw
        else throw "generateUnits: systemd inventory entries must be strings or attribute sets";
      path =
        if item ? path && isString item.path
        then item.path
        else throw "generateUnits: systemd inventory entry has no string path";
      components = splitString "/" path;
      rootMatches = filter (root: hasPrefix root path) allRoots;
      root =
        if length rootMatches == 1
        then head rootMatches
        else throw "generateUnits: invalid systemd inventory path '${path}' in ${builtins.toString pkg}";
      logicalPath = lib.removePrefix root path;
      safe =
        path != ""
        && !(hasPrefix "/" path)
        && !(lib.hasSuffix "/" path)
        && !(elem "" components)
        && !(elem "." components)
        && !(elem ".." components)
        && logicalPath != "";
      source = "${builtins.toString pkg}/${path}";
    in
      if !safe
      then throw "generateUnits: unsafe systemd inventory path '${path}' in ${builtins.toString pkg}"
      else {
        inherit logicalPath owner path root source;
        # Upstream copied symlinks preserve their authored target. Ordinary
        # systemd.packages leaves always point at the package path itself.
        upstreamTarget =
          if !(item ? upstreamTarget) || isString item.upstreamTarget
          then item.upstreamTarget or source
          else throw "generateUnits: upstreamTarget for '${path}' must be a string";
      };

    entriesFor = pkg: owner:
      builtins.map (normalizeInventoryEntry pkg owner) (inventoryOf pkg);

    packageKey = pkg:
      builtins.unsafeDiscardStringContext (builtins.toString pkg);
    uniquePackagesByPath = builtins.listToAttrs (builtins.map (pkg:
      lib.nameValuePair (packageKey pkg) pkg)
    packages);
    uniquePackages = builtins.attrValues uniquePackagesByPath;
    normalPackageEntries = concatLists (builtins.map (pkg: let
      owner = packageOwners.${packageKey pkg} or "@base";
    in
      filter (entry: elem entry.root normalRoots) (entriesFor pkg owner))
    uniquePackages);

    upstreamInventory =
      if upstreamUnits == [] && upstreamWants == []
      then []
      else if package == null
      then throw "generateUnits: upstreamUnits/upstreamWants require package"
      else filter (entry: entry.root == upstreamRoot) (entriesFor package "@base");
    requestedUpstreamEntries = concatLists (
      builtins.map (name: let
        matches = filter (entry: entry.logicalPath == name) upstreamInventory;
      in
        if length matches == 1
        then matches
        else throw "generateUnits: upstream unit '${name}' is missing or ambiguous in systemdUnitInventory.${type}"
      ) upstreamUnits
      ++ builtins.map (wanted: let
        prefix = "${wanted}/";
        matches = filter (entry: hasPrefix prefix entry.logicalPath) upstreamInventory;
      in
        if matches != []
        then matches
        else throw "generateUnits: upstream wants directory '${wanted}' is missing from systemdUnitInventory.${type}"
      ) upstreamWants
    );

    allExternalEntries = normalPackageEntries ++ requestedUpstreamEntries;
    externalNames = builtins.map (entry: entry.logicalPath) allExternalEntries;
    duplicateExternalNames = filter
      (name: length (filter (candidate: candidate == name) externalNames) > 1)
      (lib.unique externalNames);

    # Automatic override selection must observe the package inventory just as
    # the historical builder observed `$out/$name` after constructing the
    # package symlink farm.
    hasExternalUnit = name: elem name externalNames;
    renderUnit = name: unit: let
      requested = attrByPath ["overrideStrategy"] "asDropinIfExists" unit;
      collides = hasExternalUnit name;
      effective =
        if requested == "asDropin"
        then "asDropin"
        else if requested == "asDropinIfExists" && collides && unit.enable
        then
          if allowCollisions
          then "asDropin"
          else throw "generateUnits: multiple derivations configure ${name}"
        else requested;
    in {
      inherit name;
      text =
        if unit.text == null
        then ""
        else unit.text;
      mode = "0644";
      enable = unit.enable;
      overrideStrategy = effective;
      aliases = unit.aliases or [];
      wantedBy = unit.wantedBy or [];
      requiredBy = unit.requiredBy or [];
      upheldBy = unit.upheldBy or [];
      jobScriptKeys = builtins.map (job: job.key) (unit.jobScripts or []);
    };
    renderedUnits = mapAttrs renderUnit units;

    # These historical `ln -sfn` sites replace an existing package leaf.
    replacingPaths = lib.unique (concatLists (mapAttrsToList (name: unit:
      optional (unit.overrideStrategy != "asDropin") name
      ++ unit.aliases
      ++ builtins.map (target: "${target}.wants/${name}") unit.wantedBy
      ++ builtins.map (target: "${target}.requires/${name}") unit.requiredBy
      ++ builtins.map (target: "${target}.upholds/${name}") unit.upheldBy)
    renderedUnits));
    survivingExternalEntries = filter
      (entry: !(elem entry.logicalPath replacingPaths))
      allExternalEntries;
    externalRecords = builtins.listToAttrs (builtins.map (entry:
      lib.nameValuePair "/package/${entry.logicalPath}" {
        name = entry.logicalPath;
        text = "";
        mode = "0644";
        enable = true;
        overrideStrategy = "external";
        aliases = [];
        wantedBy = [];
        requiredBy = [];
        upheldBy = [];
        jobScriptKeys = [];
        externalEntry = {
          kind = "symlink";
          target =
            if entry.root == upstreamRoot
            then entry.upstreamTarget
            else entry.source;
        };
        inherit (entry) owner;
      })
    survivingExternalEntries);
  in
    if duplicateExternalNames != []
    then throw "generateUnits: package/upstream unit collision at ${concatStringsSep ", " duplicateExternalNames}"
    else
      builtins.seq typeDir (externalRecords // renderedUnits);

  # unitsToEtc — flatten pure unit records into manifest `/etc` entries.
  # This is shared by the config manifest and role exposure so the pure plan
  # and the materialized directory cannot acquire independent layout rules.
  unitsToEtc = units: let
    checkedEntries = description: entries: let
      names = builtins.map (entry: entry.name) entries;
      conflicts = builtins.filter
        (name:
          builtins.any
          (candidate:
            candidate != name
            && (hasPrefix "${name}/" candidate || hasPrefix "${candidate}/" name))
          names
          || builtins.length (builtins.filter (candidate: candidate == name) names) > 1)
        (lib.unique names);
    in
      if conflicts == []
      then builtins.listToAttrs entries
      else throw "${description} overlap at final /etc target(s): ${builtins.concatStringsSep ", " conflicts}";
    unitEntries = concatLists (mapAttrsToList (key: unit: let
      name = unit.name or key;
      unitPath =
        if unit.overrideStrategy == "asDropin"
        then "${name}.d/overrides.conf"
        else name;
    in
      if unit ? externalEntry
      then [
        (lib.nameValuePair "systemd/system/${unitPath}" unit.externalEntry)
      ]
      else [
        (lib.nameValuePair "systemd/system/${unitPath}" (
        if unit.enable
        then {
          kind = "text";
          inherit (unit) text mode;
        }
        else {
          kind = "symlink";
          target = "/dev/null";
        }
      ))
      ]) units);

    installEntries = concatLists (mapAttrsToList (key: unit: let
      name = unit.name or key;
    in
      if unit ? externalEntry
      then []
      else
      builtins.map (alias:
        lib.nameValuePair "systemd/system/${alias}" {
          kind = "symlink";
          target = name;
        })
      unit.aliases
      ++ builtins.map (target:
        lib.nameValuePair "systemd/system/${target}.wants/${name}" {
          kind = "symlink";
          target = "../${name}";
        })
      unit.wantedBy
      ++ builtins.map (target:
        lib.nameValuePair "systemd/system/${target}.requires/${name}" {
          kind = "symlink";
          target = "../${name}";
        })
      unit.requiredBy
      ++ builtins.map (target:
        lib.nameValuePair "systemd/system/${target}.upholds/${name}" {
          kind = "symlink";
          target = "../${name}";
        })
      unit.upheldBy)
    units);
  in
    checkedEntries "systemd unit/install entries" (unitEntries ++ installEntries);

  # Mirror `unitsToEtc`'s complete leaf layout while retaining the owner of
  # the source unit. This stays pure data and deliberately keys aliases and
  # install symlinks to the unit they point at, not to the target directory.
  unitsToOwnership = units: owners: let
    entries = concatLists (mapAttrsToList (key: unit: let
      name = unit.name or key;
      owner = unit.owner or (owners.${name} or (throw "unitsToOwnership: missing owner for ${name}"));
      unitPath =
        if unit.overrideStrategy == "asDropin"
        then "${name}.d/overrides.conf"
        else name;
      owned = path: lib.nameValuePair "systemd/system/${path}" owner;
    in
      if unit ? externalEntry
      then [(owned unitPath)]
      else
        [(owned unitPath)]
        ++ builtins.map owned unit.aliases
        ++ builtins.map (target: owned "${target}.wants/${name}") unit.wantedBy
        ++ builtins.map (target: owned "${target}.requires/${name}") unit.requiredBy
        ++ builtins.map (target: owned "${target}.upholds/${name}") unit.upheldBy
    )
    units);
  in
    let
      names = builtins.map (entry: entry.name) entries;
      conflicts = builtins.filter
        (name:
          builtins.any
          (candidate:
            candidate != name
            && (hasPrefix "${name}/" candidate || hasPrefix "${candidate}/" name))
          names
          || builtins.length (builtins.filter (candidate: candidate == name) names) > 1)
        (lib.unique names);
    in
      if conflicts == []
      then builtins.listToAttrs entries
      else throw "systemd ownership entries overlap at final /etc target(s): ${builtins.concatStringsSep ", " conflicts}";

  # materializeUnits — thin builder adapter for manifest systemd entries.
  materializeUnits = {
    type,
    etc,
    jobScripts ? {},
  }: let
    prefix = "systemd/system/";
    systemdEntries = filterAttrs (path: _entry: hasPrefix prefix path) etc;
    entries = builtins.listToAttrs (mapAttrsToList (path: entry:
      lib.nameValuePair (lib.removePrefix prefix path) entry
    ) systemdEntries);

    jobScriptDrvs = mapAttrs (key: script:
      pkgs.writeTextFile {
        name = "aos-job-script-${script.name}";
        executable = true;
        destination = "/aos-job-scripts/${key}";
        text = script.text;
        checkPhase = ''${pkgs.bash}/bin/bash -n "$target"'';
      })
    jobScripts;
    jobScriptKeys = attrNames jobScriptDrvs;
    jobScriptPaths = builtins.map (key: "${jobScriptDrvs.${key}}/aos-job-scripts/${key}") jobScriptKeys;
    placeholders = builtins.map (key: "#aos-jobscript:${key}#") jobScriptKeys;

    textEntries = filterAttrs (_path: entry: entry.kind == "text") entries;
    linkEntries = filterAttrs (_path: entry: entry.kind == "symlink") entries;
    unsupportedEntries = filterAttrs (_path: entry: !elem entry.kind ["text" "symlink"]) entries;
    unitDrvs = mapAttrs (path: entry:
      makeUnit path {
        enable = true;
        text = replaceStrings placeholders jobScriptPaths entry.text;
        jobScripts = [];
      })
    textEntries;

    materializeText = concatStrings (mapAttrsToList (path: unitDrv: ''
      mkdir -p "$out/$(dirname -- ${lib.escapeShellArg path})"
      ln -s ${lib.escapeShellArg "${unitDrv}/${path}"} "$out/${path}"
    '') unitDrvs);
    materializeLinks = concatStrings (mapAttrsToList (path: entry: ''
      mkdir -p "$out/$(dirname -- ${lib.escapeShellArg path})"
      target=${lib.escapeShellArg entry.target}
      case "$target" in
        /nix/store/*)
          if [ ! -e "$target" ] && [ ! -L "$target" ]; then
            echo "materializeUnits: inventory target for ${path} does not exist: $target" >&2
            exit 1
          fi
          ;;
      esac
      ln -sfn ${lib.escapeShellArg entry.target} "$out/${path}"
    '') linkEntries);
  in
    if unsupportedEntries != {}
    then throw "materializeUnits: unsupported manifest entry kinds below /etc/systemd/system"
    else
      pkgs.runCommand "${type}-units" {
        preferLocalBuild = true;
        allowSubstitutes = false;
      } ''
        mkdir -p "$out"
        ${materializeText}
        ${materializeLinks}
      '';

  # makeJobScript — render a shell-snippet service option
  # (`script=`/`preStart=`/`postStart=`/`reload=`/`preStop=`/`postStop=`)
  # into a pure data *record*, not a bare store path.
  #
  # The render/assemble split keeps evaluation pure while image assembly
  # F2): unit rendering must become host-portable pure eval, but a job
  # script's body is a function of the *evaluated* stage-2 config, so an
  # eval-only on-host evaluator must not build it. The fix carries the job
  # script's TEXT in the manifest (`manifest.jobScripts["<unit>:<slot>.0"]`)
  # and lets the imperative materializer write it to a generation-local
  # path. The on-host materializer rewrites the unit's `Exec*=` from the
  # `placeholder` token to that gen-local path.
  #
  # On the *build* side (off-host, where building is legitimate) this still
  # needs to produce a bootable gen-0 image. So the record also carries:
  #   - `drv`  — a derivation that writes the body to `$out/aos-job-scripts/<key>`
  #              (path component `aos-job-scripts` so the system golden
  #              comparator recognizes it; see lib/testing/system-
  #              characterization.nix `JOB_SCRIPT_MARKERS`);
  #   - `path` — the absolute store path of that file, plugged into the
  #              *build-side* `Exec*=` so the image boots.
  # The build-side `Exec*=` therefore changes from the old
  # `…-unit-script-<name>/bin/<name>` path to `…/aos-job-scripts/<key>` —
  # this is the single intentional ExecStart byte delta of the F2-A change
  # (the golden normalizes both forms to the script TEXT).
  #
  # Slot is the systemd directive the option feeds (`script=` → `ExecStart`,
  # `preStart=` → `ExecStartPre`, …); index is always 0 for option-derived
  # scripts (decisions.md F2). `key = "<unit>:<slot>.<index>"`.
  #
  # The script interpreter is kept as the AOS-built bash absolute path
  # (`${pkgs.bash}/bin/bash`, == `pkgs.runtimeShell`, the old
  # `writeShellScriptBin` interpreter) rather than the `#!/bin/sh` form
  # sketched in decisions.md: `/bin/sh` is forbidden by CLAUDE.md outside the
  # rootfs init chain, and job scripts also run in stage-1 (initrd) services
  # where `/bin/sh` is not guaranteed. The body is byte-equal to the old
  # `writeShellScriptBin` output modulo a trailing newline (which the golden
  # rstrips), so the inlined script text is unchanged.
  makeJobScript = {
    unit,
    slot,
    name,
    text,
    index ? 0,
  }: let
    scriptName = replaceStrings ["\\" "@"] ["-" "_"] (shellEscape name);
    key = "${unit}:${slot}.${builtins.toString index}";
    body = "#!${pkgs.bash}/bin/bash\nset -e\n\n${text}\n";
    drv = pkgs.writeTextFile {
      name = "aos-job-script-${scriptName}";
      executable = true;
      destination = "/aos-job-scripts/${key}";
      text = body;
      # Same build-time syntax guard writeShellScriptBin applied.
      checkPhase = ''${pkgs.bash}/bin/bash -n "$target"'';
    };
  in {
    inherit key name scriptName text drv;
    # Absolute build-side path for `Exec*=`; carries store context that pins
    # `drv` into the closure (so referencing `path` alone is enough).
    path = "${drv}/aos-job-scripts/${key}";
    # Verbatim body for `manifest.jobScripts[key].text`.
    body = body;
    mode = "0755";
    # Whitespace-free token the manifest puts in the rendered unit text in
    # place of `path`; the on-host materializer substitutes it for the
    # gen-local script path.
    placeholder = "#aos-jobscript:${key}#";
  };

  # ----------------------------------------------------------------------
  # Submodule config mixins
  # ----------------------------------------------------------------------

  unitConfig = {
    config,
    name,
    options,
    ...
  }: {
    config = {
      unitConfig =
        optionalAttrs (config.requires != []) {Requires = builtins.toString config.requires;}
        // optionalAttrs (config.wants != []) {Wants = builtins.toString config.wants;}
        // optionalAttrs (config.upholds != []) {Upholds = builtins.toString config.upholds;}
        // optionalAttrs (config.after != []) {After = builtins.toString config.after;}
        // optionalAttrs (config.before != []) {Before = builtins.toString config.before;}
        // optionalAttrs (config.bindsTo != []) {BindsTo = builtins.toString config.bindsTo;}
        // optionalAttrs (config.partOf != []) {PartOf = builtins.toString config.partOf;}
        // optionalAttrs (config.conflicts != []) {Conflicts = builtins.toString config.conflicts;}
        // optionalAttrs (config.requisite != []) {Requisite = builtins.toString config.requisite;}
        # switch-to-configuration `X-*` contract keys (restored, spec §6.4).
        # Each is gated on a non-default value so a default-config unit
        # emits nothing — preserving byte-identical unit text from the
        # reboot-only era. `X-Reload-Triggers` is a plain space-joined path
        # list (no `pkgs.writeText`: the reconciler reads the paths, not a
        # store file). `X-StopIfChanged` is emitted from the `serviceConfig`
        # mixin instead — `stopIfChanged` is a service-only option, so
        # reading it here would fail on non-service unit types.
        // optionalAttrs (!config.restartIfChanged) {X-RestartIfChanged = "false";}
        // optionalAttrs config.reloadIfChanged {X-ReloadIfChanged = "true";}
        // optionalAttrs (!config.stopOnRemoval) {X-StopOnRemoval = "false";}
        // optionalAttrs config.stopOnReconfiguration {X-StopOnReconfiguration = "true";}
        // optionalAttrs config.onlyManualStart {X-OnlyManualStart = "true";}
        // optionalAttrs config.notSocketActivated {X-NotSocketActivated = "true";}
        // optionalAttrs (config.reloadTriggers != []) {
          X-Reload-Triggers = builtins.toString config.reloadTriggers;
        }
        // optionalAttrs (config.description != "") {
          Description = config.description;
        }
        // optionalAttrs (config.documentation != []) {
          Documentation = builtins.toString config.documentation;
        }
        // optionalAttrs (config.onFailure != []) {
          OnFailure = builtins.toString config.onFailure;
        }
        // optionalAttrs (config.onSuccess != []) {
          OnSuccess = builtins.toString config.onSuccess;
        }
        # Matches upstream nixos/lib/systemd-lib.nix exactly, now that AOS's
        # module system threads `options` into submodule functions (see
        # audit fix 1.2). `startLimitBurst` and `startLimitIntervalSec`
        # have `types.int` with no default, so accessing `config.X` when
        # unset would throw — the `options.X.isDefined` guard avoids that.
        // optionalAttrs options.startLimitIntervalSec.isDefined {
          StartLimitIntervalSec = builtins.toString config.startLimitIntervalSec;
        }
        // optionalAttrs options.startLimitBurst.isDefined {
          StartLimitBurst = builtins.toString config.startLimitBurst;
        };
    };
  };

  serviceConfig = {
    name,
    lib,
    config,
    ...
  }: {
    config = {
      name = "${name}.service";
      environment.PATH =
        mkIf (config.path != [])
        "${makeBinPath config.path}:${makeSearchPath "sbin" config.path}";
      # `X-StopIfChanged=false` is emitted here rather than in the shared
      # `unitConfig` mixin because `stopIfChanged` is a service-only option
      # (reading it on a non-service unit type would fail). It still lands
      # in the `[Unit]` section via the merge into `config.unitConfig`.
      # Default (`true`) emits nothing (spec §6.4).
      unitConfig = optionalAttrs (!config.stopIfChanged) {X-StopIfChanged = "false";};
      # Upstream's `enableStrictShellChecks = mkOptionDefault …` assignment
      # was dropped here (spec §5.4) along with the `nixosConfig = config`
      # closure that fed it.
    };
  };

  pathConfig = {
    name,
    config,
    ...
  }: {
    config = {
      name = "${name}.path";
    };
  };

  socketConfig = {
    name,
    config,
    ...
  }: {
    config = {
      name = "${name}.socket";
    };
  };

  sliceConfig = {
    name,
    config,
    ...
  }: {
    config = {
      name = "${name}.slice";
    };
  };

  targetConfig = {
    name,
    config,
    ...
  }: {
    config = {
      name = "${name}.target";
    };
  };

  timerConfig = {
    name,
    config,
    ...
  }: {
    config = {
      name = "${name}.timer";
    };
  };

  stage2ServiceConfig = {config, ...}: {
    imports = [serviceConfig];
    # Default PATH for stage-2 services — minimal but enough to avoid
    # every script having to set `path = [...]` for basic text tools.
    # Uses AOS's package names (`pkgs.grep`, `pkgs.sed`) instead of
    # upstream's `pkgs.gnugrep` / `pkgs.gnused`, and the closure's
    # `pkgs.systemd` instead of a `cfg.package` read.
    config.path = mkIf config.enableDefaultPath (mkAfter [
      pkgs.coreutils
      pkgs.findutils
      pkgs.grep
      pkgs.sed
      pkgs.systemd
    ]);
  };

  stage1ServiceConfig = serviceConfig;

  mountConfig = {config, ...}: {
    config = {
      name = "${escapeSystemdPath config.where}.mount";
      mountConfig =
        {
          What = config.what;
          Where = config.where;
        }
        // optionalAttrs (config.type != "") {
          Type = config.type;
        }
        // optionalAttrs (config.options != "") {
          Options = config.options;
        };
    };
  };

  automountConfig = {config, ...}: {
    config = {
      name = "${escapeSystemdPath config.where}.automount";
      automountConfig = {
        Where = config.where;
      };
    };
  };

  # Render the `[Install]` directives — Alias=, WantedBy=, RequiredBy=,
  # UpheldBy= — for every unit type. Stage 2 ALSO populates .wants /
  # .requires / .upholds via `generateUnits`'s symlink farm; the
  # `[Install]` section is redundant-but-safe in that case (systemd's
  # preset/enable mechanism is idempotent if the symlinks already
  # exist). RFC-0001 package targets rely on this section as the
  # preset path: an Ignition-written preset file names the target, and
  # the every-boot `aos-preset.service` walks `[Install]` to create the
  # runtime symlink in the tmpfs /etc upper.
  commonUnitText = def: bodyLines: let
    install =
      optionalString (def.aliases != []) "Alias=${concatStringsSep " " def.aliases}\n"
      + optionalString (def.wantedBy != []) "WantedBy=${concatStringsSep " " def.wantedBy}\n"
      + optionalString (def.requiredBy != []) "RequiredBy=${concatStringsSep " " def.requiredBy}\n"
      + optionalString (def.upheldBy != []) "UpheldBy=${concatStringsSep " " def.upheldBy}\n";
  in
    (settingsToSections {Unit = def.unitConfig;})
    + bodyLines
    + optionalString (install != "") "\n[Install]\n${install}";

  # ----------------------------------------------------------------------
  # Per-unit-type renderers
  # ----------------------------------------------------------------------
  #
  # Each `*ToUnit` function takes a fully-merged submodule definition and
  # returns an attrset shaped for `generateUnits` / `makeUnit`:
  #   { name; aliases; wantedBy; requiredBy; upheldBy; enable;
  #     overrideStrategy; text; }
  # `text` is the rendered unit file; everything else drives how
  # `generateUnits` assembles symlinks and drop-ins.

  targetToUnit = def: let
    # RFC-0001 package targets are enabled by preset policy at runtime, so
    # their unit text needs an [Install] section even though the expose
    # artifact must not carry direct multi-user.target.wants symlinks.
    presetOnlyWantedBy =
      if lib.hasPrefix "aos-pkg-" def.name && lib.hasSuffix ".target" def.name && def.wantedBy == []
      then ["multi-user.target"]
      else def.wantedBy;
    textDef = def // {wantedBy = presetOnlyWantedBy;};
  in {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText textDef "";
  };

  # serviceToUnit — pure function of `def`. Upstream's
  # `env = cfg.globalEnvironment // def.environment;` merge has moved
  # out to modules/systemd/system.nix (spec §4.2) — `def.environment`
  # here is already the merged result.
  #
  # All six `X-*` switch-to-configuration emissions from upstream are
  # dropped (spec §5.2).
  serviceToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    # Carry the service's job-script records onto the rendered
    # unit so `makeUnit` can substitute each `#aos-jobscript:<key>#` placeholder
    # in `text` back to its build-side `path`. `text` keeps placeholders so the
    # eval-only manifest renders the body without forcing any job-script drv.
    inherit (def) jobScripts;
    text = commonUnitText def (
      ''
        [Service]
      ''
      + (
        let
          env = def.environment;
        in
          concatMapStrings (
            n: let
              s =
                optionalString (env.${n} != null)
                "Environment=${toJSON "${n}=${env.${n}}"}\n";
              # systemd max line length is 1 MiB since commit e6dde451a51
              # (systemd repo).
            in
              if stringLength s >= 1048576
              then throw "The value of the environment variable '${n}' in systemd service '${def.name}' is too long."
              else s
          ) (attrNames env)
      )
      + attrsToSection def.serviceConfig
    );
  };

  socketToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def ''
      [Socket]
      ${attrsToSection def.socketConfig}
      ${concatStringsSep "\n" (builtins.map (s: "ListenStream=${s}") def.listenStreams)}
      ${concatStringsSep "\n" (builtins.map (s: "ListenDatagram=${s}") def.listenDatagrams)}
    '';
  };

  timerToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def (settingsToSections {
      Timer = def.timerConfig;
    });
  };

  pathToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def (settingsToSections {
      Path = def.pathConfig;
    });
  };

  mountToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def (settingsToSections {
      Mount = def.mountConfig;
    });
  };

  automountToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def (settingsToSections {
      Automount = def.automountConfig;
    });
  };

  sliceToUnit = def: {
    inherit
      (def)
      name
      aliases
      wantedBy
      requiredBy
      upheldBy
      enable
      overrideStrategy
      ;
    text = commonUnitText def (settingsToSections {
      Slice = def.sliceConfig;
    });
  };

  # networkToText — render a systemd-networkd `.network` file body. Unlike
  # the `*ToUnit` renderers above this is NOT a unit: a `.network` lands in
  # /etc/systemd/network/ (networkd config), has no `[Unit]`/`[Install]`
  # sections, and so does not flow through `commonUnitText`/`generateUnits`.
  # It is the same INI shape as a unit body, so `settingsToSections` (and its
  # list-value → repeated-keys handling) applies directly. Empty sections are
  # filtered so an unset `dhcpV4Config` etc. emits nothing. Initrd-scoped for
  # now (boot.initrd.systemd.network); stage-2 networking.nix still hand-writes
  # its heredocs — converging it is a deliberate follow-up.
  networkToText = def:
    settingsToSections (filterAttrs (_: s: s != {}) {
      Match = def.matchConfig;
      Link = def.linkConfig;
      Network = def.networkConfig;
      DHCPv4 = def.dhcpV4Config;
      DHCPv6 = def.dhcpV6Config;
    });

  # The maximum number of characters allowed in a GPT partition label.
  # Corresponds to GPT_LABEL_MAX from systemd's gpt.h.
  GPTMaxLabelLength = 36;
}
