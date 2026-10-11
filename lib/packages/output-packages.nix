##! Creates ordinary package identities from exact outputs of one source build.
{
  name,
  package,
  definition,
  withNativeArtifacts,
  withQualification,
}: let
  output = definition.output;
  selected = package.${output};
  moduleArtifact = import ./module-source.nix {
    inherit name;
    source = definition.module or null;
  };
  # Logical package outputs are independent of the physical Nix output name.
  # Keep drvPath/outputName unchanged so publication authenticates the original
  # source build while deployment and documentation own the installable name.
  payload =
    builtins.removeAttrs selected ((package.outputs or ["out"])
      ++ [
        "deployment"
        "documentation"
        "deploymentArtifact"
        "documentationArtifact"
        "module"
        "moduleDeps"
        "qualification"
        "qualificationDocument"
        "qualificationArtifact"
        "outputPackages"
      ])
    // {
      catalogName = name;
      pname = name;
      outputs = ["out"];
      out = result;
      runtimeDeps = definition.runtimeDeps or [];
      propagatedDeps = definition.propagatedDeps or [];
      moduleDeps = definition.moduleDeps or [];
      passthru = package.passthru or {};
      meta = (package.meta or {}) // {mainProgram = name;} // (definition.meta or {});
    }
    // (
      if moduleArtifact != null
      then {module = moduleArtifact;}
      else {}
    );
  result =
    if definition ? packageProbe
    then
      withQualification {
        packageName = name;
        version = package.version;
        inherit (definition) packageProbe;
      }
      payload
    else withNativeArtifacts payload;
in
  if output == "out" || !(builtins.elem output (package.outputs or ["out"]))
  then throw "Subpackage '${name}' must select a declared non-default output."
  else result
