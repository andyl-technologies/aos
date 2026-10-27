# Selects the current Cargo invocation's test executable, including cache hits.
{
  lib,
  pkgs,
  crate,
  destination,
  target ? builtins.replaceStrings ["-"] ["_"] crate,
  kind ? "lib",
}: ''
  # Shared targets can retain older executables with the same crate prefix.
  # Cargo emits the selected artifact even when it is fresh; filenames alone
  # cannot establish which feature set and source this invocation compiled.
  libtest_executable="$(${pkgs.jq}/bin/jq --slurp --exit-status --raw-output \
    --arg target ${lib.escapeShellArg target} '
      [.[] | select(.reason == "compiler-artifact"
        and .target.name == $target and .profile.test == true
        and (.target.kind | index(${builtins.toJSON kind})) != null
        and .executable != null)]
      | if length == 1 then .[0].executable
        else error("expected exactly one selected libtest artifact") end
    ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl")"
  test -f "$libtest_executable"
  test -x "$libtest_executable"
  install -D -m 0755 "$libtest_executable" ${lib.escapeShellArg destination}
''
