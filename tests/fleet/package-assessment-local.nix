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
      first = json.loads(maintainer.succeed(command + "--idempotency-key fixture-first --evidence-output /var/lib/assessment/evidence.json"))
      assert first["execution"]["mode"] == "local", first
      findings = first["data"]["subjectResults"][0]["findings"]
      assert len(findings) == 1, findings
      assert "CVE-2026-10001" in findings[0]["advisoryIds"], findings

      advisory_command = (
          "aos --json maintain cve CVE-2026-10001 "
          "--evidence-input /var/lib/assessment/evidence.json "
      )
      advisory = json.loads(maintainer.succeed(advisory_command))
      assert advisory["execution"]["context"] == "bundle-reproduction", advisory
      page = advisory["data"]
      assert page["assessmentContext"]["inputDigest"] == first["data"]["inputDigest"], page
      assert len(page["revisions"]) == 1, page
      assert page["revisions"][0]["findingLinks"][0]["findingKey"] == findings[0]["findingKey"], page
      assert page["revisions"][0]["recordDigest"] in findings[0]["advisoryRecordDigests"], page
      miss = json.loads(maintainer.succeed(advisory_command.replace("CVE-2026-10001", "CVE-2026-99999")))
      assert miss["data"]["revisions"] == [], miss
      maintainer.fail(advisory_command + "--subject-ref absent-subject")
      maintainer.fail(advisory_command + "--resource-scope different-bundle")

      reproduced = json.loads(maintainer.succeed(
          "aos-release-fleet-fixture assessment-verify /var/lib/assessment/evidence.json"
      ))
      assert reproduced == first["data"], (reproduced, first)
      second = json.loads(maintainer.succeed(command))
      assert second["data"]["subjectResults"][0]["findings"] == findings, second

      scans_command = (
          "AOS_ROOT=/var/lib/assessment/repository aos --json maintain "
          "--state-dir /var/lib/assessment/state scans "
      )
      receipt = first["execution"]["scan"]
      assert receipt["state"] == "succeeded", receipt
      scan_id = receipt["scanId"]
      assert json.loads(maintainer.succeed(scans_command + "inspect " + scan_id))["data"] == receipt
      assert json.loads(maintainer.succeed(scans_command + "wait " + scan_id + " --timeout 1"))["data"] == receipt
      replay = json.loads(maintainer.succeed(command + "--idempotency-key fixture-first"))
      assert replay["kind"] == "assessment-scan" and replay["data"] == receipt, replay
      maintainer.fail(scans_command + "cancel " + scan_id + " --expected-revision " + str(receipt["resourceVersion"]))
      operations = json.loads(maintainer.succeed(scans_command + "list --limit 1"))["data"]
      assert len(operations["scans"]) == 1 and operations["nextScan"], operations
      next_page = json.loads(maintainer.succeed(scans_command + "list --limit 1 --after-scan " + operations["nextScan"]))["data"]
      assert len(next_page["scans"]) == 1 and "nextScan" not in next_page, next_page

      # Queue the actual CLI behind the source lane. Cancellation is admitted
      # while its per-scan process lease remains held, then finalized on start.
      namespace = receipt["request"]["resourceScope"].removeprefix("local-")
      state_repository = "/var/lib/assessment/state/repositories/" + namespace
      lock = state_repository + "/operation-locks/package-assessment.lock"
      unit_environment = "--setenv=PATH=" + shlex.quote(maintainer.succeed("printf '%s' \"$PATH\"").strip())
      maintainer.succeed("systemd-run --unit=assessment-lane-fixture aos-release-fleet-fixture assessment-lane-lock " + lock + " /var/lib/assessment/lane-ready /var/lib/assessment/lane-release")
      maintainer.wait_until_succeeds("test -f /var/lib/assessment/lane-ready")
      queued_command = command + "--idempotency-key fixture-cancel"
      maintainer.succeed("systemd-run --unit=assessment-queued-cli " + unit_environment + " --property=StandardOutput=file:/var/lib/assessment/cancelled-output.json --property=StandardError=file:/var/lib/assessment/cancelled-error.txt ${pkgs.bash}/bin/bash -c " + shlex.quote(queued_command))
      try:
          maintainer.wait_until_succeeds(scans_command + "list | jq -e --arg expected queued '.data.scans[] | select(.state == $expected)'")
      except Exception:
          print(maintainer.succeed("cat /var/lib/assessment/cancelled-error.txt"))
          print(maintainer.succeed("journalctl -u assessment-queued-cli --no-pager"))
          raise
      queued = next(scan for scan in json.loads(maintainer.succeed(scans_command + "list"))["data"]["scans"] if scan["state"] == "queued")
      assert json.loads(maintainer.succeed(scans_command + "recover"))["data"] == []
      cancelled = json.loads(maintainer.succeed(scans_command + "cancel " + queued["scanId"] + " --expected-revision " + str(queued["resourceVersion"])))
      assert cancelled["data"]["state"] == "cancelling", cancelled
      maintainer.succeed("touch /var/lib/assessment/lane-release")
      maintainer.wait_until_succeeds(scans_command + "inspect " + queued["scanId"] + " | jq -e --arg expected cancelled '.data.state == $expected'")
      maintainer.fail(scans_command + "wait " + queued["scanId"] + " --timeout 1")
      maintainer.succeed("test ! -e /var/lib/assessment/state/assessment-budget-osv.json")
      head = json.loads(maintainer.succeed("cat " + state_repository + "/assessments/journal.json"))["head"]
      assert head["scanId"] == second["execution"]["scan_id"], head

      # Cached acquisition neither reads source credentials nor consumes a
      # physical request. Its frozen request preserves the explicit intent.
      cached_command = command.replace("--offline ", "--freshness cached ")
      cached = json.loads(maintainer.succeed(cached_command + "--token-env invalid/name --nvd-key-env invalid/name"))
      assert cached["execution"]["scan"]["request"]["freshness"] == "cached", cached
      assert cached["execution"]["scan"]["usage"]["providerRequests"] == 0, cached
      assert cached["data"]["subjectResults"][0]["findings"] == findings, cached

      # An interrupted queued process loses its lease. Only explicit recovery
      # finalizes that operation; reads and repeated recovery create no work.
      maintainer.succeed("systemd-run --unit=assessment-orphan-lane-fixture aos-release-fleet-fixture assessment-lane-lock " + lock + " /var/lib/assessment/orphan-ready /var/lib/assessment/orphan-release")
      maintainer.wait_until_succeeds("test -f /var/lib/assessment/orphan-ready")
      maintainer.succeed("systemd-run --unit=assessment-orphan-cli " + unit_environment + " ${pkgs.bash}/bin/bash -c " + shlex.quote(command + "--idempotency-key fixture-orphan"))
      maintainer.wait_until_succeeds(scans_command + "list | jq -e --arg expected queued '.data.scans[] | select(.state == $expected)'")
      orphan = next(scan for scan in json.loads(maintainer.succeed(scans_command + "list"))["data"]["scans"] if scan["state"] == "queued")
      maintainer.succeed("systemctl kill --signal=KILL --kill-whom=all assessment-orphan-cli.service")
      maintainer.wait_until_succeeds("systemctl is-failed --quiet assessment-orphan-cli.service")
      recovered = json.loads(maintainer.succeed(scans_command + "recover"))["data"]
      assert len(recovered) == 1 and recovered[0]["scanId"] == orphan["scanId"], recovered
      assert recovered[0]["state"] == "superseded" and recovered[0]["failureCode"] == "local-process-interrupted", recovered
      assert json.loads(maintainer.succeed(scans_command + "recover"))["data"] == []
      maintainer.succeed("touch /var/lib/assessment/orphan-release")

      # A cooldown admitted on the prior quota day survives a new online CLI
      # process. Refused physical acquisition preserves retained evidence and
      # cannot spend quota or clear the protected host-wide source budget.
      now = int(maintainer.succeed("date +%s").strip())
      budget = json.dumps({
          "day": now // 86400 - 1,
          "requests": 999,
          "nextEligibleAt": now + 3600,
      }, separators=(",", ":"))
      budget_path = "/var/lib/assessment/state/assessment-budget-osv.json"
      maintainer.succeed("printf '%s' " + shlex.quote(budget) + " > " + budget_path)
      maintainer.succeed("chmod 600 " + budget_path)
      throttled = json.loads(maintainer.succeed(command.replace("--offline ", "")))
      assert "source-acquisition-incomplete" in throttled["execution"]["diagnostics"], throttled
      assert throttled["execution"]["scan"]["state"] == "partial", throttled
      assert maintainer.succeed("cat " + budget_path) == budget
      assert throttled["data"]["subjectResults"][0]["findings"] == findings, throttled

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
      maintainer.fail(advisory_command.replace("evidence.json", "tampered.json"))
    '';
}
