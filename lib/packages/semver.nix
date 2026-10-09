##! Pure SemVer checks for build-time module dependency selection.
##! Runtime solving uses Rust semver; both sides check the same authored ranges.
let
  split = pattern: value: builtins.filter builtins.isString (builtins.split pattern value);
  item = values: index: builtins.elemAt values index;
  numeric = value: builtins.match "[0-9]+" value != null;
  compareText = left: right:
    if left == right
    then 0
    else if left < right
    then -1
    else 1;
  compareNumber = left: right:
    if builtins.stringLength left == builtins.stringLength right
    then compareText left right
    else compareText (builtins.stringLength left) (builtins.stringLength right);
  unsigned = value:
    builtins.match "0|[1-9][0-9]*" value
    != null
    && compareNumber value "18446744073709551615" <= 0;
  identifiers = prerelease: value:
    builtins.all (part:
      builtins.match "[0-9A-Za-z-]+" part
      != null
      && (!prerelease || !numeric part || builtins.match "0|[1-9][0-9]*" part != null))
    (split "\\." value);
  parse = partial: value: let
    parts = builtins.match "([^-+]+)(-([^+]+))?(\\+(.+))?" value;
    core =
      if parts == null
      then []
      else split "\\." (item parts 0);
    count = builtins.length core;
    pre =
      if parts == null || item parts 2 == null
      then ""
      else item parts 2;
    build =
      if parts == null || item parts 4 == null
      then ""
      else item parts 4;
    valid =
      # A comparator belongs to a bounded range, not the shorter exact-version
      # field used for package identities. Rust accepts long range identifiers.
      builtins.stringLength value
      <= (
        if partial
        then 4096
        else 128
      )
      && parts != null
      && count >= 1
      && count <= 3
      && (partial || count == 3)
      && builtins.all unsigned core
      && (pre == "" || (count == 3 && identifiers true pre))
      && (build == "" || (count == 3 && identifiers false build));
  in
    if !valid
    then throw "Invalid semantic version '${value}'."
    else {
      major = item core 0;
      minor =
        if count >= 2
        then item core 1
        else null;
      patch =
        if count == 3
        then item core 2
        else null;
      inherit pre;
    };
  parseVersion = parse false;
  comparePre = left: right: let
    compareParts = leftParts: rightParts:
      if leftParts == [] || rightParts == []
      then compareText (builtins.length leftParts) (builtins.length rightParts)
      else let
        leftHead = builtins.head leftParts;
        rightHead = builtins.head rightParts;
        compared =
          if numeric leftHead && numeric rightHead
          then compareNumber leftHead rightHead
          else if numeric leftHead
          then -1
          else if numeric rightHead
          then 1
          else compareText leftHead rightHead;
      in
        if compared != 0
        then compared
        else compareParts (builtins.tail leftParts) (builtins.tail rightParts);
  in
    if left == right
    then 0
    else if left == ""
    then 1
    else if right == ""
    then -1
    else compareParts (split "\\." left) (split "\\." right);
  trim = value: builtins.head (builtins.match " *([^ ].*[^ ]|[^ ]|) *" value);
  comparator = text: let
    matched = builtins.match "(>=|<=|>|<|=|~|\\^)? *(.*)" (trim text);
    rawOp = item matched 0;
    rawVersion = item matched 1;
    wild = builtins.match "([0-9]+)(\\.([0-9]+))?\\.[xX*](\\.[xX*])?" rawVersion;
    any = builtins.elem rawVersion ["*" "x" "X"];
    wildcard = wild != null;
    version =
      if any
      then null
      else if wildcard
      then
        parse true ((item wild 0)
          + (
            if item wild 2 == null
            then ""
            else ".${item wild 2}"
          ))
      else parse true rawVersion;
    op =
      if rawOp != null
      then rawOp
      else if wildcard || any
      then "="
      else "^";
    valid =
      (!any || rawOp == null)
      && (!wildcard || item wild 2 == null || item wild 3 == null);
  in
    if !valid
    then throw "Invalid semantic version comparator '${text}'."
    else {inherit op version;};
  parseRequirement = value: let
    parts =
      if builtins.isString value
      then split "," value
      else [];
    count = builtins.length parts;
    parsed = builtins.map comparator parts;
  in
    if !builtins.isString value || value == "" || builtins.stringLength value > 4096 || count > 32
    then throw "Semantic version requirement must contain 1–32 comparators and at most 4096 bytes."
    else if count > 1 && builtins.any (entry: entry.version == null) parsed
    then throw "A wildcard must be the only semantic version comparator."
    else builtins.deepSeq parsed parsed;
  matchesComparator = requirement: version:
    if requirement.version == null
    then true
    else let
      expected = requirement.version;
      major = compareNumber version.major expected.major;
      minor =
        if expected.minor == null
        then 0
        else compareNumber version.minor expected.minor;
      patch =
        if expected.patch == null
        then 0
        else compareNumber version.patch expected.patch;
      pre = comparePre version.pre expected.pre;
      same = major == 0 && minor == 0 && patch == 0 && pre == 0;
      ordered =
        if major != 0
        then major
        else if expected.minor == null
        then 0
        else if minor != 0
        then minor
        else if expected.patch == null
        then 0
        else if patch != 0
        then patch
        else pre;
      caret =
        major
        == 0
        && (
          if expected.minor == null
          then true
          else if expected.patch == null
          then
            (
              if expected.major != "0"
              then minor >= 0
              else minor == 0
            )
          else if expected.major != "0"
          then minor > 0 || (minor == 0 && (patch > 0 || (patch == 0 && pre >= 0)))
          else if expected.minor != "0"
          then minor == 0 && (patch > 0 || (patch == 0 && pre >= 0))
          else minor == 0 && patch == 0 && pre >= 0
        );
    in
      if requirement.op == "="
      then same
      else if requirement.op == ">"
      then ordered > 0
      else if requirement.op == ">="
      then same || ordered > 0
      else if requirement.op == "<"
      then ordered < 0
      else if requirement.op == "<="
      then same || ordered < 0
      else if requirement.op == "~"
      then major == 0 && minor == 0 && (patch > 0 || (patch == 0 && pre >= 0))
      else caret;
  matches = requirement: text: let
    comparators = parseRequirement requirement;
    version = parseVersion text;
    acceptsPrerelease =
      version.pre
      == ""
      || builtins.any (entry:
        entry.version
        != null
        && entry.version.pre != ""
        && entry.version.major == version.major
        && entry.version.minor == version.minor
        && entry.version.patch == version.patch)
      comparators;
  in
    acceptsPrerelease && builtins.all (entry: matchesComparator entry version) comparators;
in {
  inherit parseVersion parseRequirement matches;
}
