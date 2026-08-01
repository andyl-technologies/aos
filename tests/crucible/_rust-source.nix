{
  lib,
  entry,
  fragmentDirs ? [],
}: let
  readRustTree = path: let
    entries = builtins.readDir path;
    names = builtins.sort builtins.lessThan (builtins.attrNames entries);
    readEntry = name: let
      kind = entries.${name};
      child = path + "/${name}";
    in
      if kind == "directory"
      then readRustTree child
      else if kind == "regular" && lib.hasSuffix ".rs" name
      then builtins.readFile child
      else "";
  in
    builtins.concatStringsSep "\n" (map readEntry names);
in
  builtins.concatStringsSep "\n" (
    [(builtins.readFile entry)]
    ++ map readRustTree fragmentDirs
  )
