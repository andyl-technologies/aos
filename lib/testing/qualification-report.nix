##! Adapts a retained live qualification report to the canonical response.
{pkgs}: {
  name,
  identity,
  reportPath,
}: let
  quote = value: "'" + builtins.replaceStrings ["'"] ["'\\''"] value + "'";
in
  assert identity != "";
  assert builtins.substring 0 1 reportPath == "/";
    pkgs.writeShellScriptBin name ''
      # The coordinator writes the same request to request.json before the
      # scenario starts. Drain stdin so large requests cannot block its writer.
      ${pkgs.coreutils}/bin/cat >/dev/null

      exec ${pkgs.aos}/bin/aos release qualification respond \
        --request request.json \
        --scenarios scenario-registry.json \
        --report ${quote reportPath} \
        --identity ${quote identity}
    ''
