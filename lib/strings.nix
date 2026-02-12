# lib/strings.nix — String utility functions
#
# Functions for manipulating and constructing strings.
#

rec {
  # -- Concatenation --

  # concatStrings :: [string] -> string
  # Concatenate a list of strings with no separator.
  concatStrings = builtins.concatStringsSep "";

  # concatStringsSep :: string -> [string] -> string
  # Concatenate a list of strings with a separator.
  concatStringsSep = builtins.concatStringsSep;

  # concatMapStrings :: (a -> string) -> [a] -> string
  # Map a function over a list and concatenate the resulting strings.
  concatMapStrings = f: list:
    concatStrings (builtins.map f list);

  # concatMapStringsSep :: string -> (a -> string) -> [a] -> string
  # Map a function over a list and concatenate with a separator.
  concatMapStringsSep = sep: f: list:
    builtins.concatStringsSep sep (builtins.map f list);

  # concatLines :: [string] -> string
  # Concatenate strings separated by newlines, with a trailing newline.
  concatLines = list:
    builtins.concatStringsSep "\n" list + "\n";

  # -- Measurement --

  # stringLength :: string -> int
  stringLength = builtins.stringLength;

  # isString :: a -> bool
  isString = builtins.isString;

  # -- Prefix/suffix operations --

  # hasPrefix :: string -> string -> bool
  # Test whether a string starts with a given prefix.
  hasPrefix = prefix: str:
    let
      pLen = builtins.stringLength prefix;
      sLen = builtins.stringLength str;
    in pLen <= sLen && builtins.substring 0 pLen str == prefix;

  # hasSuffix :: string -> string -> bool
  # Test whether a string ends with a given suffix.
  hasSuffix = suffix: str:
    let
      sufLen = builtins.stringLength suffix;
      strLen = builtins.stringLength str;
    in sufLen <= strLen &&
       builtins.substring (strLen - sufLen) sufLen str == suffix;

  # removePrefix :: string -> string -> string
  # Remove a prefix from a string if present, otherwise return unchanged.
  removePrefix = prefix: str:
    let pLen = builtins.stringLength prefix;
    in if hasPrefix prefix str
       then builtins.substring pLen (builtins.stringLength str - pLen) str
       else str;

  # removeSuffix :: string -> string -> string
  # Remove a suffix from a string if present, otherwise return unchanged.
  removeSuffix = suffix: str:
    let
      sufLen = builtins.stringLength suffix;
      strLen = builtins.stringLength str;
    in if hasSuffix suffix str
       then builtins.substring 0 (strLen - sufLen) str
       else str;

  # -- Replacement --

  # replaceStrings :: [string] -> [string] -> string -> string
  replaceStrings = builtins.replaceStrings;

  # -- Case conversion --

  # toLower :: string -> string
  toLower = str:
    builtins.replaceStrings
      [ "A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
        "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z" ]
      [ "a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
        "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z" ]
      str;

  # toUpper :: string -> string
  toUpper = str:
    builtins.replaceStrings
      [ "a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
        "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z" ]
      [ "A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
        "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z" ]
      str;

  # -- Splitting --

  # splitString :: string -> string -> [string]
  # Split a string by a separator.
  # splitString "." "a.b.c" == ["a" "b" "c"]
  splitString = sep: str:
    let
      parts = builtins.split (escapeRegex sep) str;
      # builtins.split returns interleaved matches and non-matches.
      # Non-matches are strings, matches are lists. We want only the strings.
    in builtins.filter builtins.isString parts;

  # -- Conditional --

  # optionalString :: bool -> string -> string
  # Return the string if condition is true, otherwise empty string.
  optionalString = cond: str: if cond then str else "";

  # -- Formatting --

  # fixedWidthString :: int -> string -> string -> string
  # Pad a string to a fixed width using a fill character (on the left).
  # fixedWidthString 5 "0" "42" == "00042"
  fixedWidthString = width: fill: str:
    let
      strLen = builtins.stringLength str;
      fillLen = builtins.stringLength fill;
    in if strLen >= width then str
       else let
         needed = width - strLen;
         padding = concatStrings (
           builtins.genList (_: fill) (needed / fillLen + 1)
         );
       in builtins.substring (builtins.stringLength padding - needed) needed padding + str;

  # fixedWidthNumber :: int -> int -> string
  # Format an integer with zero-padding to a fixed width.
  # fixedWidthNumber 3 7 == "007"
  fixedWidthNumber = width: n:
    fixedWidthString width "0" (builtins.toString n);

  # -- Shell escaping --

  # escapeShellArg :: string -> string
  # Escape a string for safe use as a shell argument.
  escapeShellArg = arg: "'${builtins.replaceStrings ["'"] ["'\\''"] (builtins.toString arg)}'";

  # escapeShellArgs :: [string] -> string
  # Escape and join a list of strings as shell arguments.
  escapeShellArgs = args:
    builtins.concatStringsSep " " (builtins.map escapeShellArg args);

  # toShellVar :: string -> string -> string
  # Create a shell variable assignment.
  # toShellVar "FOO" "bar baz" == "FOO='bar baz'"
  toShellVar = name: value:
    "${name}=${escapeShellArg value}";

  # toShellVars :: attrset -> string
  # Create shell variable assignments from an attrset, one per line.
  toShellVars = vars:
    builtins.concatStringsSep "\n" (
      builtins.map (name: toShellVar name (builtins.toString vars.${name}))
        (builtins.attrNames vars)
    );

  # -- Path construction --

  # makeBinPath :: [derivation | string] -> string
  # Construct a colon-separated PATH from a list of derivations or store paths.
  makeBinPath = paths:
    builtins.concatStringsSep ":" (builtins.map (p: "${builtins.toString p}/bin") paths);

  # makeSearchPath :: string -> [derivation | string] -> string
  # Like makeBinPath but for an arbitrary subdirectory.
  # makeSearchPath "lib" [pkg1 pkg2] == "/nix/store/...-pkg1/lib:/nix/store/...-pkg2/lib"
  makeSearchPath = subDir: paths:
    builtins.concatStringsSep ":" (
      builtins.map (p: "${builtins.toString p}/${subDir}") paths
    );

  # makeLibraryPath :: [derivation | string] -> string
  makeLibraryPath = makeSearchPath "lib";

  # makeIncludePath :: [derivation | string] -> string
  makeIncludePath = makeSearchPath "include";

  # makePkgConfigPath :: [derivation | string] -> string
  makePkgConfigPath = makeSearchPath "lib/pkgconfig";

  # -- Regex --

  # escapeRegex :: string -> string
  # Escape special regex characters in a string for use with builtins.match/split.
  escapeRegex = str:
    builtins.replaceStrings
      [ "\\" "." "^" "$" "*" "+" "?" "(" ")" "[" "]" "{" "}" "|" ]
      [ "\\\\" "\\." "\\^" "\\$" "\\*" "\\+" "\\?" "\\(" "\\)" "\\[" "\\]" "\\{" "\\}" "\\|" ]
      str;

  # match :: string -> string -> [string] | null
  # Test if a string matches a regex, returning captured groups or null.
  match = builtins.match;

  # -- Normalization --

  # trim :: string -> string
  # Remove leading and trailing whitespace.
  trim = str:
    let
      # Match leading whitespace, content, trailing whitespace
      m = builtins.match "[ \t\n\r]*(.*[^ \t\n\r])[ \t\n\r]*" str;
    in if m == null then "" else builtins.elemAt m 0;

  # normalizePath :: string -> string
  # Remove trailing slashes and collapse double slashes in a path string.
  normalizePath = path:
    let
      # Remove trailing slashes (keep at least one char)
      withoutTrailing = removeSuffix "/" path;
      result = if withoutTrailing == "" then "/" else withoutTrailing;
    in result;

  # fileContents :: path -> string
  # Read a file and strip trailing newline.
  fileContents = file:
    removeSuffix "\n" (builtins.readFile file);

  # -- Conversion --

  # toString :: a -> string
  # Convert a value to string using builtins.toString.
  toString = builtins.toString;

  # toInt :: string -> int
  # Parse a string as an integer. Throws on invalid input.
  toInt = str:
    let
      parsed = builtins.fromJSON str;
    in if builtins.isInt parsed then parsed
       else throw "toInt: '${str}' is not a valid integer";

  # floatToString :: float -> string
  floatToString = builtins.toString;

  # -- Multi-line --

  # indent :: int -> string -> string
  # Indent each line of a multi-line string by n spaces.
  indent = n: str:
    let
      pad = concatStrings (builtins.genList (_: " ") n);
      lines = splitString "\n" str;
    in builtins.concatStringsSep "\n" (builtins.map (line:
      if line == "" then "" else pad + line
    ) lines);
}
