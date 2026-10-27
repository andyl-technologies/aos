##! Cargo workspace source shaping for dependency-artifact derivations.
##!
##! The dummy source identity includes Cargo manifests and Rust target paths,
##! but deliberately excludes Rust file contents. This lets Nix reuse a
##! dependency build after an ordinary implementation edit while still
##! invalidating it when manifests or the target layout change.
{
  lib,
  mkDerivation,
}: let
  isCargoBuildDirectory = import ./_cargo-build-directory.nix;
  generatedDirectory = root: path: let
    name = baseNameOf path;
  in
    builtins.elem name [".git" ".direnv" ".worktrees" ".crucible"]
    || lib.hasPrefix "result-" name
    || isCargoBuildDirectory root path;

  excludedDirectory = root: relative: name:
    generatedDirectory root (root + "/${lib.optionalString (relative != "") "${relative}/"}${name}")
    || (relative == "" && name == "result");

  collectRustTargets = root: relative: let
    directory =
      if relative == ""
      then root
      else root + "/${relative}";
    entries = builtins.readDir directory;
  in
    lib.concatMap
    (name: let
      kind = entries.${name};
      child =
        if relative == ""
        then name
        else "${relative}/${name}";
    in
      if kind == "directory" && !excludedDirectory root relative name
      then collectRustTargets root child
      else if kind == "regular" && lib.hasSuffix ".rs" name
      then [child]
      else [])
    (builtins.attrNames entries);
in {
  mkCargoDummySource = {
    srcRoot,
    name ? "cargo-dummy-source",
    cargoRoot ? null,
  }: let
    srcRootString = toString srcRoot;
    workspaceManifest = builtins.fromTOML (builtins.readFile (srcRoot + "/Cargo.toml"));
    cratesIoPatches = workspaceManifest.patch."crates-io" or {};
    patchedCrates = builtins.filter (path: path != null) (
      lib.mapAttrsToList (_: patch: patch.path or null) cratesIoPatches
    );
    isPatchedCratePath = relative:
      builtins.any
      (crate: relative == crate || lib.hasPrefix "${crate}/" relative)
      patchedCrates;
    patchedCrateInput = pathString:
      builtins.any
      (crate: let
        cratePath = "${srcRootString}/${crate}";
      in
        pathString
        == cratePath
        || lib.hasPrefix "${cratePath}/" pathString
        || lib.hasPrefix "${pathString}/" cratePath)
      patchedCrates;
    rustTargets = builtins.filter (relative: !isPatchedCratePath relative) (collectRustTargets srcRoot "");
    manifestSource = builtins.path {
      path = srcRoot;
      name = "${name}-manifests";
      filter = path: type: let
        base = baseNameOf path;
        pathString = toString path;
      in
        if type == "directory"
        then !generatedDirectory srcRoot path && toString path != "${toString srcRoot}/result"
        else
          patchedCrateInput pathString
          || builtins.elem base [
            "Cargo.toml"
            "Cargo.lock"
            "config"
            "config.toml"
            "rust-toolchain"
            "rust-toolchain.toml"
          ];
    };
    rustTargetsFile = builtins.toFile "${name}-rust-targets" (
      lib.concatStringsSep "\n" rustTargets + "\n"
    );
  in
    mkDerivation {
      pname = name;
      version = "1";
      src = null;
      phases = [
        {
          name = "install";
          script = ''
            destination="$out${lib.optionalString (cargoRoot != null) "/${cargoRoot}"}"
            mkdir -p "$destination"
            cp -R "${manifestSource}/." "$destination/"
            chmod -R u+w "$destination"
            while IFS= read -r relative; do
              test -n "$relative" || continue
              mkdir -p "$destination/$(dirname "$relative")"
              printf '#![allow(dead_code)]\nfn main() {}\n' > "$destination/$relative"
            done < ${rustTargetsFile}
          '';
        }
      ];
      preferLocalBuild = true;
      allowSubstitutes = false;
    };
}
