{
  lib,
  entry,
  fragmentDirs ? [],
  includeTests ? true,
}: let
  isTestPath = path:
    lib.hasInfix "/tests/" (toString path)
    || lib.hasSuffix "/tests" (toString path)
    || lib.hasSuffix "/tests.rs" (toString path)
    || lib.hasSuffix "_tests.rs" (toString path)
    || lib.hasSuffix "_test.rs" (toString path);

  rustFilesInTree = path: let
    entries = builtins.readDir path;
    names = builtins.sort builtins.lessThan (builtins.attrNames entries);
    readEntry = name: let
      kind = entries.${name};
      child = path + "/${name}";
    in
      if !includeTests && isTestPath child
      then []
      else if kind == "directory"
      then rustFilesInTree child
      else if kind == "regular" && lib.hasSuffix ".rs" name
      then [child]
      else [];
  in
    builtins.concatLists (map readEntry names);

  # Module splits can put tests beside their entry file rather than in the
  # conventional module directory. Follow explicit Rust path attributes so
  # source contracts continue to inspect those implementations and regressions.
  referencedFiles = path:
    builtins.concatMap (line: let
      matched = builtins.match ''[[:space:]]*#[[]path[[:space:]]*=[[:space:]]*"([^"]+)"[]][[:space:]]*'' line;
      referenced = builtins.toPath (builtins.dirOf path + "/${builtins.head matched}");
    in
      if matched != null && builtins.pathExists referenced && lib.hasSuffix ".rs" referenced && (includeTests || !isTestPath referenced)
      then [(toString referenced)]
      else [])
    (lib.splitString "\n" (builtins.readFile path));

  collectFiles = visited: pending:
    if pending == []
    then visited
    else let
      path = builtins.head pending;
      remaining = builtins.tail pending;
    in
      if builtins.elem path visited
      then collectFiles visited remaining
      else collectFiles (visited ++ [path]) (remaining ++ referencedFiles path);
  files = collectFiles [] (map toString ([entry] ++ builtins.concatMap rustFilesInTree fragmentDirs));
in
  builtins.concatStringsSep "\n" (map builtins.readFile files)
