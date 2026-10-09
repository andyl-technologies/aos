# Cargo names remain independent of the directory hierarchy.
{lib}: let
  cratesDir = ../../crates;
  workspace = builtins.fromTOML (builtins.readFile (cratesDir + "/Cargo.toml"));
  entries = map (member: let
    directory = cratesDir + "/${member}";
    manifest = builtins.fromTOML (builtins.readFile (directory + "/Cargo.toml"));
  in {
    name = manifest.package.name;
    value = directory;
  }) workspace.workspace.members;
  directories = builtins.listToAttrs entries;
in {
  inherit directories;
  packageNames = builtins.attrNames directories;
  cruciblePackages = builtins.filter (lib.hasPrefix "crucible-") (builtins.attrNames directories);
  packageDir = package: directories.${package};
}
