# Portable package vulnerability assessment and evidence handoff through the CLI.
{
  mkSystem,
  pkgs,
  ...
}: let
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.aos
        pkgs.aos.testSupport
        pkgs.git
        pkgs.nix
        pkgs.jq
      ];
    }
  ];
in {
  name = "package-assessment-local";
  timeout = 900;
  bootTimeout = 300;
  machines.maintainer = {
    inherit system;
    memoryMiB = 4096;
    varSizeMiB = 2048;
  };
  testScript =
    # python
    ''
      import json
      import shlex

      maintainer.wait_for_unit("multi-user.target", timeout=240)
      maintainer.succeed("mkdir -p /var/lib/assessment/repository")
      maintainer.succeed("printf '%s\\n' '{}' > /var/lib/assessment/repository/default.nix")
      maintainer.succeed("git -C /var/lib/assessment/repository init")
      maintainer.succeed("git -C /var/lib/assessment/repository remote add origin https://example.org/assessment-fixture.git")
      command = (
          "AOS_ROOT=/var/lib/assessment/repository "
          "aos --json maintain --state-dir /var/lib/assessment/state scan "
          "--profile vulnerabilities --offline --assessment-input /var/lib/assessment/input.json "
          "--package fixture/example "
      )
      maintainer.succeed("aos-release-fleet-fixture assessment-input 1.2.0 > /var/lib/assessment/input.json")
      first = json.loads(maintainer.succeed(command + "--evidence-output /var/lib/assessment/evidence.json"))
      assert first["execution"]["mode"] == "local", first
      findings = first["data"]["subjectResults"][0]["findings"]
      assert len(findings) == 1, findings
      assert "CVE-2026-10001" in findings[0]["advisoryIds"], findings

      reproduced = json.loads(maintainer.succeed(
          "aos-release-fleet-fixture assessment-verify /var/lib/assessment/evidence.json"
      ))
      assert reproduced == first["data"], (reproduced, first)
      second = json.loads(maintainer.succeed(command))
      assert second["data"]["subjectResults"][0]["findings"] == findings, second

      # An unknown selector and an existing export destination both fail before
      # publishing misleading success or overwriting the retained handoff.
      maintainer.fail(command.replace("fixture/example", "fixture/absent"))
      maintainer.fail(command + "--evidence-output /var/lib/assessment/evidence.json")
      assert json.loads(maintainer.succeed(
          "aos-release-fleet-fixture assessment-verify /var/lib/assessment/evidence.json"
      )) == reproduced

      # A newly assessed immutable version does not inherit the older
      # inventory's bindings. The fixed version has no affected finding.
      maintainer.succeed("aos-release-fleet-fixture assessment-input 1.3.0 > /var/lib/assessment/input.json")
      fixed = json.loads(maintainer.succeed(command))
      assert fixed["data"]["subjectResults"][0]["findings"] == [], fixed
      assert fixed["data"]["inputDigest"] != first["data"]["inputDigest"], fixed

      # Tampering with the handoff cannot manufacture an accepted result.
      bundle = json.loads(maintainer.succeed("cat /var/lib/assessment/evidence.json"))
      bundle["assessment"]["subjectResults"][0]["findings"] = []
      encoded = shlex.quote(json.dumps(bundle))
      maintainer.succeed("printf '%s' " + encoded + " > /var/lib/assessment/tampered.json")
      maintainer.fail("aos-release-fleet-fixture assessment-verify /var/lib/assessment/tampered.json")
    '';
}
