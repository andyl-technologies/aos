##! Packages a native qualification adapter without putting live state in Nix.
{pkgs}: {
  name,
  platform,
  identity,
  scenarios,
  workRoot,
  timeoutSeconds ? 1800,
}: let
  registry = pkgs.writeTextFile {
    name = "${name}-scenarios";
    text = builtins.toJSON {
      schema_version = "aos.release.qualification-scenarios/v1";
      inherit platform scenarios;
    };
  };
  quote = value: "'" + builtins.replaceStrings ["'"] ["'\\''"] value + "'";
in
  assert builtins.elem platform ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
  assert timeoutSeconds > 0 && timeoutSeconds <= 21600;
  assert builtins.substring 0 1 workRoot == "/";
    pkgs.writeShellScriptBin name ''
      exec ${pkgs.aos}/bin/aos release qualification execute \
        --scenarios ${registry} \
        --identity ${quote identity} \
        --work-root ${quote workRoot} \
        --timeout-seconds ${toString timeoutSeconds}
    ''
