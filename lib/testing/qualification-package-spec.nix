##! Projects a signed package probe into the qualification runner's input.
{lib}: {
  packageName,
  packageProbe,
}: let
  toolMarkers = {
    bash = "@bash@";
    "c-compiler" = "@cc@";
    "cxx-compiler" = "@cxx@";
    python = "@python@";
  };
  renderFragment = fragment:
    if fragment.kind == "literal"
    then fragment.text
    else if fragment.kind == "artifact-root"
    then
      if fragment.artifact.output == "out"
      then "@out@"
      else "@output:${fragment.artifact.output}@"
    else if fragment.kind == "artifact-path"
    then
      (
        if fragment.artifact.output == "out"
        then "@out@"
        else "@output:${fragment.artifact.output}@"
      )
      + "/${fragment.path}"
    else if fragment.kind == "work-path"
    then "@work@/${fragment.path}"
    else toolMarkers.${fragment.tool};
  renderTemplate = template:
    builtins.concatStringsSep "" (map renderFragment template.fragments);
  renderOptionalTemplate = template:
    if template == null
    then null
    else {exact = renderTemplate template;};
  renderStep = step: {
    argv = map renderTemplate step.argv;
    stdin =
      if step.stdin == null
      then null
      else renderTemplate step.stdin;
    stdout = renderOptionalTemplate step.stdout;
    stderr = renderOptionalTemplate step.stderr;
    inherit (step) exit_code timeout_seconds observes_rejection;
  };
  renderOperation = operation: {
    inherit (operation) input expected artifacts;
    operation = operation.operation;
    files = builtins.mapAttrs (_: renderTemplate) operation.files;
    steps = map renderStep operation.steps;
  };
in {
  schema_version = "aos.release.package-probe/v1";
  package = packageName;
  primary = renderOperation packageProbe.primary;
  bad_input = renderOperation packageProbe.bad_input;
}
