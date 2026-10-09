##! Packages a native qualification adapter without putting live state in Nix.
{pkgs}: {
  name,
  platform,
  identity,
  scenarios,
  caseScenarios ? {},
  scenarioFixtures ? {},
  workRoot,
  timeoutSeconds ? 1800,
}: let
  registryInputs = pkgs.writeTextFile {
    name = "${name}-scenario-inputs";
    destination = "/inputs.json";
    text = builtins.toJSON {
      registry = {
        schema_version = "aos.release.qualification-scenarios/v1";
        inherit platform scenarios;
      } // (if caseScenarios == {} then {} else {case_scenarios = caseScenarios;});
      fixtures = builtins.mapAttrs (_: fixture: builtins.toString fixture) scenarioFixtures;
    };
  };
  registry = pkgs.mkDerivation {
    pname = "${name}-scenarios";
    version = "1";
    src = null;
    buildDeps = [pkgs.python3];
    dontStrip = true;
    dontNukeRefs = true;
    phases = [{
      name = "bind-fixtures";
      script = ''
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
          ${./qualification-fixture-commitments-self-test.py} \
          ${./qualification-fixture-commitments.py}
        mkdir -p "$out"
        PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
          ${./qualification-fixture-commitments.py} \
          ${registryInputs}/inputs.json "$out/scenarios.json"
      '';
    }];
  };
  quote = value: "'" + builtins.replaceStrings ["'"] ["'\\''"] value + "'";
  registryPath = "${registry}/scenarios.json";
  executor = pkgs.writeShellScriptBin name ''
    exec ${pkgs.aos}/bin/aos maintain release step qualification execute \
      --scenarios ${registryPath} \
      --identity ${quote identity} \
      --work-root ${quote workRoot} \
      --timeout-seconds ${toString timeoutSeconds}
  '';
in
  assert builtins.elem platform ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
  assert timeoutSeconds > 0 && timeoutSeconds <= 21600;
  assert builtins.substring 0 1 workRoot == "/";
    executor
    // {
      passthru =
        (executor.passthru or {})
        // {
          qualification = {
            inherit identity platform registryPath scenarios caseScenarios scenarioFixtures;
            registryArtifact = registry;
          };
        };
    }
