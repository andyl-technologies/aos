##! lib/strings.nix — String utility functions
##!
##! Functions for manipulating and constructing strings.
rec {
  ## # Concatenation

  ## Concatenate a list of strings with no separator.
  ## # Type
  ## `[string] -> string`
  concatStrings = builtins.concatStringsSep "";

  ## Concatenate a list of strings with a separator.
  ## # Type
  ## `string -> [string] -> string`
  concatStringsSep = builtins.concatStringsSep;

  ## Map a function over a list and concatenate the resulting strings.
  ## # Type
  ## `(a -> string) -> [a] -> string`
  concatMapStrings = f: list: concatStrings (builtins.map f list);

  ## Map a function over a list and concatenate with a separator.
  ## # Type
  ## `string -> (a -> string) -> [a] -> string`
  concatMapStringsSep = sep: f: list:
    builtins.concatStringsSep sep (builtins.map f list);

  ## Concatenate strings separated by newlines, with a trailing newline.
  ## # Type
  ## `[string] -> string`
  concatLines = list: builtins.concatStringsSep "\n" list + "\n";

  ## # Measurement

  ## # Type
  ## `string -> int`
  stringLength = builtins.stringLength;

  ## # Type
  ## `a -> bool`
  isString = builtins.isString;

  ## # Prefix/suffix operations

  ## Test whether a string starts with a given prefix.
  ## # Type
  ## `string -> string -> bool`
  hasPrefix = prefix: str: let
    pLen = builtins.stringLength prefix;
    sLen = builtins.stringLength str;
  in
    pLen <= sLen && builtins.substring 0 pLen str == prefix;

  ## Test whether a string ends with a given suffix.
  ## # Type
  ## `string -> string -> bool`
  hasSuffix = suffix: str: let
    sufLen = builtins.stringLength suffix;
    strLen = builtins.stringLength str;
  in
    sufLen <= strLen && builtins.substring (strLen - sufLen) sufLen str == suffix;

  ## Test whether a string contains a given substring anywhere.
  ##
  ## The empty needle is contained in every string. Otherwise the needle is
  ## present exactly when deleting it changes the haystack.
  ## # Type
  ## `string -> string -> bool`
  hasInfix = needle: haystack:
    needle
    == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

  ## Remove a prefix from a string if present, otherwise return unchanged.
  ## # Type
  ## `string -> string -> string`
  removePrefix = prefix: str: let
    pLen = builtins.stringLength prefix;
  in
    if hasPrefix prefix str
    then builtins.substring pLen (builtins.stringLength str - pLen) str
    else str;

  ## Remove a suffix from a string if present, otherwise return unchanged.
  ## # Type
  ## `string -> string -> string`
  removeSuffix = suffix: str: let
    sufLen = builtins.stringLength suffix;
    strLen = builtins.stringLength str;
  in
    if hasSuffix suffix str
    then builtins.substring 0 (strLen - sufLen) str
    else str;

  ## # Replacement

  ## # Type
  ## `[string] -> [string] -> string -> string`
  replaceStrings = builtins.replaceStrings;

  ## # Case conversion

  ## # Type
  ## `string -> string`
  toLower = str:
    builtins.replaceStrings
    [
      "A"
      "B"
      "C"
      "D"
      "E"
      "F"
      "G"
      "H"
      "I"
      "J"
      "K"
      "L"
      "M"
      "N"
      "O"
      "P"
      "Q"
      "R"
      "S"
      "T"
      "U"
      "V"
      "W"
      "X"
      "Y"
      "Z"
    ]
    [
      "a"
      "b"
      "c"
      "d"
      "e"
      "f"
      "g"
      "h"
      "i"
      "j"
      "k"
      "l"
      "m"
      "n"
      "o"
      "p"
      "q"
      "r"
      "s"
      "t"
      "u"
      "v"
      "w"
      "x"
      "y"
      "z"
    ]
    str;

  ## # Type
  ## `string -> string`
  toUpper = str:
    builtins.replaceStrings
    [
      "a"
      "b"
      "c"
      "d"
      "e"
      "f"
      "g"
      "h"
      "i"
      "j"
      "k"
      "l"
      "m"
      "n"
      "o"
      "p"
      "q"
      "r"
      "s"
      "t"
      "u"
      "v"
      "w"
      "x"
      "y"
      "z"
    ]
    [
      "A"
      "B"
      "C"
      "D"
      "E"
      "F"
      "G"
      "H"
      "I"
      "J"
      "K"
      "L"
      "M"
      "N"
      "O"
      "P"
      "Q"
      "R"
      "S"
      "T"
      "U"
      "V"
      "W"
      "X"
      "Y"
      "Z"
    ]
    str;

  ## # Splitting

  ## Split a string by a separator.
  ##
  ## `splitString "." "a.b.c" == ["a" "b" "c"]`
  ## # Type
  ## `string -> string -> [string]`
  splitString = sep: str: let
    parts = builtins.split (escapeRegex sep) str;
    # builtins.split returns interleaved matches and non-matches.
    # Non-matches are strings, matches are lists. We want only the strings.
  in
    builtins.filter builtins.isString parts;

  ## # Conditional

  ## Return the string if condition is true, otherwise empty string.
  ## # Type
  ## `bool -> string -> string`
  optionalString = cond: str:
    if cond
    then str
    else "";

  ## # Formatting

  ## Pad a string to a fixed width using a fill character (on the left).
  ##
  ## `fixedWidthString 5 "0" "42" == "00042"`
  ## # Type
  ## `int -> string -> string -> string`
  fixedWidthString = width: fill: str: let
    strLen = builtins.stringLength str;
    fillLen = builtins.stringLength fill;
  in
    if strLen >= width
    then str
    else let
      needed = width - strLen;
      padding = concatStrings (builtins.genList (_: fill) (needed / fillLen + 1));
    in
      builtins.substring (builtins.stringLength padding - needed) needed padding + str;

  ## Format an integer with zero-padding to a fixed width.
  ##
  ## `fixedWidthNumber 3 7 == "007"`
  ## # Type
  ## `int -> int -> string`
  fixedWidthNumber = width: n: fixedWidthString width "0" (builtins.toString n);

  ## Percent-encode a string for use in URI components and `data:` URLs.
  ##
  ## builtins.replaceStrings scans the input and emits replacements without
  ## rescanning the output, so listing `%` first is safe.
  ## # Type
  ## `string -> string`
  uriEncode =
    builtins.replaceStrings
    ["%" "\n" "\r" "\t" " " "!" "\"" "#" "$" "&" "'" "(" ")" "*" "+" "," "/" ":" ";" "<" "=" ">" "?" "@" "[" "\\" "]" "^" "`" "{" "|" "}"]
    ["%25" "%0A" "%0D" "%09" "%20" "%21" "%22" "%23" "%24" "%26" "%27" "%28" "%29" "%2A" "%2B" "%2C" "%2F" "%3A" "%3B" "%3C" "%3D" "%3E" "%3F" "%40" "%5B" "%5C" "%5D" "%5E" "%60" "%7B" "%7C" "%7D"];

  ## # Shell escaping

  ## Escape a string for safe use as a shell argument.
  ## # Type
  ## `string -> string`
  escapeShellArg = arg: "'${builtins.replaceStrings ["'"] ["'\\''"] (builtins.toString arg)}'";

  ## Escape and join a list of strings as shell arguments.
  ## # Type
  ## `[string] -> string`
  escapeShellArgs = args: builtins.concatStringsSep " " (builtins.map escapeShellArg args);

  ## Create a shell variable assignment.
  ##
  ## `toShellVar "FOO" "bar baz" == "FOO='bar baz'"`
  ## # Type
  ## `string -> string -> string`
  toShellVar = name: value: "${name}=${escapeShellArg value}";

  ## Create shell variable assignments from an attrset, one per line.
  ## # Type
  ## `attrset -> string`
  toShellVars = vars:
    builtins.concatStringsSep "\n" (
      builtins.map (name: toShellVar name (builtins.toString vars.${name})) (builtins.attrNames vars)
    );

  ## # Path construction

  ## Construct a colon-separated PATH from a list of derivations or store paths.
  ## # Type
  ## `[derivation | string] -> string`
  makeBinPath = paths: builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") paths);

  ## Like makeBinPath but for an arbitrary subdirectory.
  ##
  ## `makeSearchPath "lib" [pkg1 pkg2] == "/nix/store/...-pkg1/lib:/nix/store/...-pkg2/lib"`
  ## # Type
  ## `string -> [derivation | string] -> string`
  makeSearchPath = subDir: paths:
    builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/${subDir}") paths);

  ## # Type
  ## `[derivation | string] -> string`
  makeLibraryPath = makeSearchPath "lib";

  ## # Type
  ## `[derivation | string] -> string`
  makeIncludePath = makeSearchPath "include";

  ## # Type
  ## `[derivation | string] -> string`
  makePkgConfigPath = makeSearchPath "lib/pkgconfig";

  ## # Regex

  ## Escape special regex characters in a string for use with builtins.match/split.
  ## # Type
  ## `string -> string`
  escapeRegex = str:
    builtins.replaceStrings
    [
      "\\"
      "."
      "^"
      "$"
      "*"
      "+"
      "?"
      "("
      ")"
      "["
      "]"
      "{"
      "}"
      "|"
    ]
    [
      "\\\\"
      "\\."
      "\\^"
      "\\$"
      "\\*"
      "\\+"
      "\\?"
      "\\("
      "\\)"
      "\\["
      "\\]"
      "\\{"
      "\\}"
      "\\|"
    ]
    str;

  ## Test if a string matches a regex, returning captured groups or null.
  ## # Type
  ## `string -> string -> [string] | null`
  match = builtins.match;

  ## # Normalization

  ## Remove leading and trailing whitespace.
  ## # Type
  ## `string -> string`
  trim = str: let
    # Match leading whitespace, content, trailing whitespace
    m = builtins.match "[ \t\n\r]*(.*[^ \t\n\r])[ \t\n\r]*" str;
  in
    if m == null
    then ""
    else builtins.elemAt m 0;

  ## Remove trailing slashes and collapse double slashes in a path string.
  ## # Type
  ## `string -> string`
  normalizePath = path: let
    # Remove trailing slashes (keep at least one char)
    withoutTrailing = removeSuffix "/" path;
    result =
      if withoutTrailing == ""
      then "/"
      else withoutTrailing;
  in
    result;

  ## Read a file and strip trailing newline.
  ## # Type
  ## `path -> string`
  fileContents = file: removeSuffix "\n" (builtins.readFile file);

  ## # Conversion

  ## Convert a value to string using builtins.toString.
  ## # Type
  ## `a -> string`
  toString = builtins.toString;

  ## Parse a string as an integer. Throws on invalid input.
  ## # Type
  ## `string -> int`
  toInt = str: let
    parsed = builtins.fromJSON str;
  in
    if builtins.isInt parsed
    then parsed
    else throw "toInt: '${str}' is not a valid integer";

  ## # Type
  ## `float -> string`
  floatToString = builtins.toString;

  ## # Multi-line

  ## Indent each line of a multi-line string by n spaces.
  ## # Type
  ## `int -> string -> string`
  indent = n: str: let
    pad = concatStrings (builtins.genList (_: " ") n);
    lines = splitString "\n" str;
  in
    builtins.concatStringsSep "\n" (builtins.map (line:
      if line == ""
      then ""
      else pad + line)
    lines);
}
