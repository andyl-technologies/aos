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
#   - `makeJobScript` always uses `pkgs.writeShellScriptBin`; the
#     `writeShellApplication` / shellcheck branch is dropped because AOS
#     has no Haskell toolchain (spec §5.4).
#   - `generateUnits` keeps its `upstreamUnits` / `upstreamWants` parameters
#     so the future initrd builder can cherry-pick stage-1 units from the
#     systemd package, but drops the `type == "system"` tail that
#     manufactures default.target / ctrl-alt-del.target / multi-user.target
#     .wants symlinks — systemd finds those natively via the patched
#     SYSTEM_DATA_UNIT_DIR lookup. See spec §5.5.
#   - `lndir` is replaced by a plain shell loop that walks
#     `$pkg/etc/systemd/<type>` and `$pkg/lib/systemd/<type>`. See §5.6.
#   - All six `X-*` switch-to-configuration emissions are dropped
#     (`X-Restart-Triggers`, `X-Reload-Triggers`, `X-RestartIfChanged`,
#     `X-ReloadIfChanged`, `X-StopIfChanged`, `X-NotSocketActivated`).
#     AOS uses sysupdate-based rolling updates with reboots, not in-place
#     systemctl reconciliation. See spec §5.2.
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
  # so _lib.nix stays a pure library without pulling in a utils module).
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
  escapeC = charsToEscape: s: let
    toHex = c: let
      n = builtins.substring 0 1 "${builtins.toString (builtins.elemAt [0 1 2 3 4 5 6 7 8 9] c)}";
    in
      n;
    # We only need the subset of ASCII that systemd path escaping touches,
    # so a small lookup table is enough. Values are lowercase two-digit hex.
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

  mkPathSafeName = replaceStrings ["@" ":" "\\" "[" "]"] ["-" "-" "-" "" ""];

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
    then
      pkgs.runCommand "unit-${mkPathSafeName name}" {
        preferLocalBuild = true;
        allowSubstitutes = false;
        # unit.text can be null for disabled units; passAsFile with a null
        # variable is a no-op in Nix, so guard with optionalString to avoid
        # the mv call failing on a missing $textPath.
        text = optionalString (unit.text != null) unit.text;
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

  # generateUnits — assemble the final unit directory.
  #
  # Signature retains `upstreamUnits` and `upstreamWants` so the future
  # initrd builder (tier ii, outside this refactor; see spec §5.5) can
  # cherry-pick default stage-1 units from `${package}/lib/systemd/system/`.
  # Stage-2 callers (modules/systemd/system.nix) pass `[]` for both,
  # because AOS systemd's SYSTEM_DATA_UNIT_DIR patch makes upstream
  # `/lib/systemd/system/` findable natively at runtime.
  #
  # `package` defaults to `pkgs.systemd` rather than reading a NixOS
  # `systemd.package` option, per spec §3.2. `packages` has no default
  # and must be supplied by the caller (system.nix passes
  # `config.systemd.packages`).
  generateUnits = {
    allowCollisions ? true,
    type,
    units,
    upstreamUnits,
    upstreamWants,
    packages,
    package ? pkgs.systemd,
  }: let
    typeDir =
      {
        system = "system";
        initrd = "system";
        user = "user";
        nspawn = "nspawn";
      }
      .${type};
  in
    pkgs.runCommand "${type}-units" {
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      mkdir -p $out

      # TODO(tier-ii-initrd): upstream walks $package/example/systemd/$typeDir/
      # but AOS's systemd ships units at $package/lib/systemd/system/ (the
      # move to example/ is a nixpkgs-specific install step AOS does not
      # perform). When the initrd builder starts passing non-empty
      # upstreamUnits/upstreamWants, rewrite the `fn=...` assignments
      # below to use lib/systemd/$typeDir instead. For tier-i stage-2
      # the loops run over empty lists and the mismatch is harmless.

      # Copy the upstream systemd units we're interested in.
      for i in ${builtins.toString upstreamUnits}; do
        fn=${package}/example/systemd/${typeDir}/$i
        if ! [ -e $fn ]; then echo "missing $fn"; false; fi
        if [ -L $fn ]; then
          target="$(readlink "$fn")"
          if [ ''${target:0:3} = ../ ]; then
            ln -s "$(readlink -f "$fn")" $out/
          else
            cp -pd $fn $out/
          fi
        else
          ln -s $fn $out/
        fi
      done

      # Copy .wants links, but only those that point to units that
      # we're interested in.
      for i in ${builtins.toString upstreamWants}; do
        fn=${package}/example/systemd/${typeDir}/$i
        if ! [ -e $fn ]; then echo "missing $fn"; false; fi
        x=$out/$(basename $fn)
        mkdir $x
        for i in $fn/*; do
          y=$x/$(basename $i)
          cp -pd $i $y
          if ! [ -e $y ]; then rm $y; fi
        done
      done

      # Symlink all unit files provided by `systemd.packages`.
      #
      # Replacement for the upstream `lndir`-based loop (spec §5.6).
      # Walks both `$pkg/etc/systemd/$typeDir` and `$pkg/lib/systemd/$typeDir`
      # (matching upstream's feature set), handling drop-in dirs
      # (`foo.service.d/`) and `.wants/` dirs by re-creating the directory
      # and symlinking each entry individually, so merges across multiple
      # packages work. Plain unit files become single symlinks.
      packages="${builtins.toString packages}"
      declare -A unique_packages
      for k in $packages; do unique_packages[$k]=1; done

      for i in "''${!unique_packages[@]}"; do
        for base in "$i/etc/systemd/${typeDir}" "$i/lib/systemd/${typeDir}"; do
          [ -d "$base" ] || continue
          for fn in "$base"/*; do
            [ -e "$fn" ] || continue
            bn=$(basename "$fn")
            if [ -d "$fn" ]; then
              # Drop-in dirs (.d) and .wants dirs: recreate the directory
              # and symlink each entry individually so merges work.
              mkdir -p "$out/$bn"
              for inner in "$fn"/*; do
                [ -e "$inner" ] || continue
                ln -s "$inner" "$out/$bn/$(basename "$inner")"
              done
            else
              ln -s "$fn" "$out/$bn"
            fi
          done
        done
      done

      # Symlink units defined by systemd.units where override strategy
      # shall be automatically detected. If these are also provided by
      # systemd or systemd.packages, add them as <unit-name>.d/overrides.conf
      # so they extend the upstream unit instead of replacing it.
      for i in ${
        builtins.toString (
          mapAttrsToList (_n: v: v.unit) (
            filterAttrs (
              _n: v: (attrByPath ["overrideStrategy"] "asDropinIfExists" v) == "asDropinIfExists"
            )
            units
          )
        )
      }; do
        fn=$(basename $i/*)
        if [ -e $out/$fn ]; then
          if [ "$(readlink -f $i/$fn)" = /dev/null ]; then
            ln -sfn /dev/null $out/$fn
          else
            ${
        if allowCollisions
        then ''
          mkdir -p $out/$fn.d
          ln -s $i/$fn $out/$fn.d/overrides.conf
        ''
        else ''
          echo "Found multiple derivations configuring $fn!"
          exit 1
        ''
      }
          fi
       else
          ln -fs $i/$fn $out/
        fi
      done

      # Symlink units defined by systemd.units which shall be
      # treated as drop-in file.
      for i in ${
        builtins.toString (
          mapAttrsToList (_n: v: v.unit) (
            filterAttrs (_n: v: v ? overrideStrategy && v.overrideStrategy == "asDropin") units
          )
        )
      }; do
        fn=$(basename $i/*)
        mkdir -p $out/$fn.d
        ln -s $i/$fn $out/$fn.d/overrides.conf
      done

      # Create service aliases from aliases option.
      ${concatStrings (
        mapAttrsToList (
          name: unit:
            concatMapStrings (name2: ''
              ln -sfn '${name}' $out/'${name2}'
            '') (unit.aliases or [])
        )
        units
      )}

      # Create .wants, .upholds and .requires symlinks from the wantedBy,
      # upheldBy and requiredBy options.
      ${concatStrings (
        mapAttrsToList (
          name: unit:
            concatMapStrings (name2: ''
              mkdir -p $out/'${name2}.wants'
              ln -sfn '../${name}' $out/'${name2}.wants'/
            '') (unit.wantedBy or [])
        )
        units
      )}

      ${concatStrings (
        mapAttrsToList (
          name: unit:
            concatMapStrings (name2: ''
              mkdir -p $out/'${name2}.upholds'
              ln -sfn '../${name}' $out/'${name2}.upholds'/
            '') (unit.upheldBy or [])
        )
        units
      )}

      ${concatStrings (
        mapAttrsToList (
          name: unit:
            concatMapStrings (name2: ''
              mkdir -p $out/'${name2}.requires'
              ln -sfn '../${name}' $out/'${name2}.requires'/
            '') (unit.requiredBy or [])
        )
        units
      )}

      # (Upstream's `type == "system"` tail that manufactures default.target,
      # ctrl-alt-del.target, and multi-user.target.wants/remote-fs.target is
      # intentionally omitted — AOS systemd finds those natively at
      # /lib/systemd/system/ via SYSTEM_DATA_UNIT_DIR. See spec §5.5.)
    ''; # */

  # makeJobScript — compile a shell snippet into a derivation whose main
  # binary is the script. Returns the absolute path of that binary so
  # callers can plug it into `ExecStart=` directly. Simplified vs. upstream
  # per spec §5.4: shellcheck / writeShellApplication branch removed.
  makeJobScript = {
    name,
    text,
  }: let
    scriptName = replaceStrings ["\\" "@"] ["-" "_"] (shellEscape name);
    out =
      (
        pkgs.writeShellScriptBin scriptName ''
          set -e

          ${text}
        ''
      )
      .overrideAttrs (_: {
        # The derivation name is different from the script file name
        # to keep the script file name short and avoid cluttering logs.
        name = "unit-script-${scriptName}";
      });
  in
    lib.getExe out;

  # ----------------------------------------------------------------------
  # Submodule config mixins
  # ----------------------------------------------------------------------

  unitConfig = {
    config,
    name,
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
        # Upstream's `X-Restart-Triggers` / `X-Reload-Triggers` emissions
        # were dropped here (spec §5.2): they use `pkgs.writeText` (which
        # the AOS port doesn't bring in) and are consumed only by
        # `switch-to-configuration`, which AOS doesn't use.
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
        # AOS adaptation: AOS's module system does not currently pass
        # `options` to submodule functions, so `options.X.isDefined` is
        # not available. The ported options declare `startLimitBurst` /
        # `startLimitIntervalSec` with `default = null` and type
        # `nullOr int`, and we check against null here.
        // optionalAttrs (config.startLimitIntervalSec != null) {
          StartLimitIntervalSec = builtins.toString config.startLimitIntervalSec;
        }
        // optionalAttrs (config.startLimitBurst != null) {
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

  commonUnitText = def: bodyLines:
    (settingsToSections {Unit = def.unitConfig;})
    + bodyLines
    + optionalString (def.wantedBy != []) ''

      [Install]
      WantedBy=${concatStringsSep " " def.wantedBy}
    '';

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

  targetToUnit = def: {
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
    text = settingsToSections {Unit = def.unitConfig;};
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

  # The maximum number of characters allowed in a GPT partition label.
  # Corresponds to GPT_LABEL_MAX from systemd's gpt.h.
  GPTMaxLabelLength = 36;
}
