# Selects script inodes before running the interpreter-pinning pass.
{filter ? null}: {
  setup =
    if filter == null
    then ""
    else ''
      source_runtime_inputs="$TMPDIR/binutils-source-runtime-inputs"
      mkdir "$source_runtime_inputs"
      ${filter}/bin/perl ${../../filter-runtime-scripts.pl} . "$source_runtime_inputs"
    '';

  root =
    if filter == null
    then "."
    else ''"$source_runtime_inputs"'';

  cleanup =
    if filter == null
    then ""
    else "\nrm -r \"$source_runtime_inputs\"";
}
