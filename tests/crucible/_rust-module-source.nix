# Reads one Rust module together with the files it was split into: a
# `<module>/` fragment directory and, on request, its `<module>_test.rs` /
# `<module>_tests.rs` siblings; a crate root (`lib.rs` or `main.rs`) stands for
# every module under its `src`. Gates read the result as one text so a needle
# keeps matching after a module is split.
{
  lib,
  entry,
  # Include `<module>_test.rs` / `<module>_tests.rs` siblings; off by default
  # so gates that forbid patterns do not scan test doubles.
  siblingTests ? false,
}: let
  filename = builtins.baseNameOf entry;
  moduleName = lib.removeSuffix ".rs" filename;
  parent = builtins.dirOf entry;
  siblings = builtins.readDir parent;
  isCrateRoot = moduleName == "lib" || moduleName == "main";
  # A crate root stands for the whole crate: every module under `src`.
  fragmentDir =
    if isCrateRoot
    then parent
    else parent + "/${moduleName}";
  siblingTestFiles =
    builtins.filter
    (name: siblingTests && builtins.hasAttr name siblings)
    ["${moduleName}_test.rs" "${moduleName}_tests.rs"];
in
  builtins.concatStringsSep "\n" (
    [
      (import ./_rust-source.nix {
        inherit lib entry;
        fragmentDirs = lib.optional (builtins.pathExists fragmentDir) fragmentDir;
      })
    ]
    ++ map (name: builtins.readFile (parent + "/${name}")) siblingTestFiles
  )
