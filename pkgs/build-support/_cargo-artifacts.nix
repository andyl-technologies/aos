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
  generatedDirectory = name:
    builtins.elem name [".git" ".direnv" ".worktrees" "result" "target"]
    || lib.hasPrefix "result-" name
    || lib.hasPrefix "target-" name;

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
      if kind == "directory" && !generatedDirectory name
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
    rustTargets = collectRustTargets srcRoot "";
    manifestSource = builtins.path {
      path = srcRoot;
      name = "${name}-manifests";
      filter = path: type: let
        base = baseNameOf path;
      in
        if type == "directory"
        then !generatedDirectory base
        else
          builtins.elem base [
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
