{lib}: let
  readRustDirectory = directory: let
    entries = builtins.readDir directory;
    names = builtins.sort builtins.lessThan (builtins.attrNames entries);
    rustFiles = builtins.filter (name:
      entries.${name} == "regular" && lib.hasSuffix ".rs" name)
    names;
  in
    builtins.concatStringsSep "\n" (map (name:
      builtins.readFile (directory + "/${name}"))
    rustFiles);
in
  builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-cli/src/main.rs)
    (readRustDirectory ../../crates/crucible-cli/src/cli)
    (builtins.readFile ../../crates/crucible-cli/src/tests.rs)
    (readRustDirectory ../../crates/crucible-cli/src/tests)
  ]
