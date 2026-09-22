##! Executes the installed Workers runtime without library-path overrides.
{
  runCommand,
  workerd,
}:
runCommand "workerd-installed-runtime-check" {} ''
  mkdir -p test
  cp ${./runtime-check.capnp} test/config.capnp
  cp ${./runtime-check.js} test/runtime-check.js

  # Checking the installed output catches runpaths lost during reference scrubbing.
  unset LD_LIBRARY_PATH
  ${workerd}/bin/workerd test test/config.capnp

  mkdir -p "$out"
  printf '%s\n' 'Installed Workers runtime checks passed.' > "$out/result"
''
