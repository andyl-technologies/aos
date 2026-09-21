# Selects script inodes before running the interpreter-pinning pass.
{
  filter ? null,
  sourceRoot ? ".",
  temporaryName ? "binutils-source-runtime-inputs",
  temporaryRoot ? "$TMPDIR",
  filterProgram ? ../../filter-runtime-scripts.pl,
}: {
  setup =
    if filter == null
    then ""
    else ''
      source_runtime_inputs="${temporaryRoot}/${temporaryName}"
      mkdir "$source_runtime_inputs"
      ${filter}/bin/perl ${filterProgram} ${sourceRoot} "$source_runtime_inputs"
    '';

  root =
    if filter == null
    then sourceRoot
    else ''"$source_runtime_inputs"'';

  cleanup =
    if filter == null
    then ""
    else "\nrm -r \"$source_runtime_inputs\"";
}
