##! Projects a signed package probe into the qualification runner's input.
{lib}: {
  packageName,
  packageProbe,
}: let
  toolMarkers = {
    bash = "@bash@";
    "c-compiler" = "@cc@";
    "cxx-compiler" = "@cxx@";
    perl = "@perl@";
    python = "@python@";
    "rust-compiler" = "@rustc@";
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
  renderStep = step:
    {
      argv = map renderTemplate step.argv;
      inherit (step) exit_code observes_rejection;
    }
    // lib.optionalAttrs (step.stdin != null) {stdin = renderTemplate step.stdin;}
    // lib.optionalAttrs (step.stdout != null) {stdout.exact = renderTemplate step.stdout;}
    // lib.optionalAttrs (step.stderr != null) {stderr.exact = renderTemplate step.stderr;}
    // lib.optionalAttrs (step.timeout_seconds != null) {inherit (step) timeout_seconds;};
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
