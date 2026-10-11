##! Keeps the public guest-agent output distinct from its generated script.
{pkgs}: let
  package = pkgs.aos-test-agent;
  script = builtins.head package.runtimeDeps;
  ownerBindings = builtins.filter (binding: binding.selector.package == "aos-test-agent") package.qualificationDocument.artifacts;
in {
  exactPublicOutput = assert ownerBindings
  == [
    {
      selector = {
        package = "aos-test-agent";
        output = "out";
      };
      path = builtins.toString package;
    }
  ]; true;
  distinctPrivateScript = assert script.name == "aos-test-agent-script";
  assert script.meta.mainProgram == "aos-test-agent";
  assert builtins.toString script != builtins.toString package; true;
}
