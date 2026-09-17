##! Adapts a retained live qualification report to the canonical response.
{pkgs}: {
  name,
  identity,
  reportPath ? null,
  reportRoot ? null,
}: let
  quote = value: "'" + builtins.replaceStrings ["'"] ["'\\''"] value + "'";
  reportArgument =
    if reportPath != null
    then "--report ${quote reportPath}"
    else "--report-root ${quote reportRoot}";
in
  assert identity != "";
  assert (reportPath == null) != (reportRoot == null);
  assert builtins.substring 0 1 (
    if reportPath != null
    then reportPath
    else reportRoot
  )
  == "/";
    pkgs.writeShellScriptBin name ''
      # The coordinator writes the same request to request.json before the
      # scenario starts. Drain stdin so large requests cannot block its writer.
      ${pkgs.coreutils}/bin/cat >/dev/null

      exec ${pkgs.aos}/bin/aos release qualification respond \
        --request request.json \
        --scenarios scenario-registry.json \
        ${reportArgument} \
        --identity ${quote identity}
    ''
