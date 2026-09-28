##! Applies pinned registry and upstream source patches to a Bazel module.
{buildPackages}: {
  pname,
  version,
  source,
  patches,
  patchStrip ? 1,
  moduleFile ? null,
}:
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
        + builtins.concatStringsSep "\n" (map (patch: "patch --batch --fuzz=0 -p${toString patchStrip} < ${patch}") patches)
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
