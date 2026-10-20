##! Applies pinned registry and upstream source patches to a Bazel module.
{buildPackages}: {
  pname,
  version,
  source,
  patches,
  patchStrip ? 1,
  moduleFile ? null,
  overlays ? {},
  overlaysAfterPatches ? false,
}: let
  overlayInstall = builtins.concatStringsSep "\n" (map (name: "install -D -m 0644 ${overlays.${name}} \"${name}\"") (builtins.attrNames overlays));
in
  buildPackages.mkDerivation {
    inherit pname version;
    src = source;
    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir module-source
          cp -a "$src"/. module-source/
          chmod -R u+w module-source
          cd module-source
        '';
      }
      {
        name = "build";
        script =
          (
            if moduleFile != null
            then "cp ${moduleFile} MODULE.bazel\n"
            else ""
          )
          + (
            if overlaysAfterPatches
            then ""
            else overlayInstall
          )
          + "\n"
          + builtins.concatStringsSep "\n" (map (patch: "patch --batch --forward --fuzz=0 -p${toString patchStrip} < ${patch}") patches)
          + (
            if overlaysAfterPatches
            then "\n" + overlayInstall
            else ""
          )
          + (
            if moduleFile != null
            then "\ncmp MODULE.bazel ${moduleFile}\n"
            else ""
          );
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a . "$out"/
        '';
      }
    ];
  }
