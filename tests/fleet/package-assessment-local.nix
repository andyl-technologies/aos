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

      status_command = (
          "AOS_ROOT=/var/lib/assessment/repository aos --json maintain "
          "--state-dir /var/lib/assessment/state status --profiles all "
      )
      baseline = json.loads(maintainer.succeed(status_command))["data"]
      profiles = baseline["subjects"][0]["profiles"]
      assert profiles[0]["profile"] == "license-signals" and profiles[0]["committedGeneration"] == 0, baseline
      assert profiles[1]["profile"] == "updates" and profiles[1]["committedGeneration"] == 0, baseline
      assert profiles[2]["profile"] == "vulnerabilities" and profiles[2]["fresh"], baseline
      assert profiles[2]["assessmentDigest"] == fixed["execution"]["scan"]["assessmentDigest"], baseline
      maintainer.fail(status_command + "--inventory-digest sha256:" + "0" * 64)
      maintainer.fail(status_command + "--active")

      # Two real CLI processes admit different profiles behind the same physical
      # source lane. Both must remain eligible and retain independent heads.
      maintainer.succeed("systemd-run --unit=assessment-profile-lane-fixture aos-release-fleet-fixture assessment-lane-lock " + lock + " /var/lib/assessment/profile-ready /var/lib/assessment/profile-release")
      maintainer.wait_until_succeeds("test -f /var/lib/assessment/profile-ready")
      update_command = command.replace("--profile vulnerabilities", "--profile updates")
      maintainer.succeed("systemd-run --unit=assessment-profile-updates " + unit_environment + " --property=StandardOutput=file:/var/lib/assessment/profile-updates.json --property=StandardError=file:/var/lib/assessment/profile-updates-error.txt ${pkgs.bash}/bin/bash -c " + shlex.quote(update_command + "--idempotency-key fixture-profile-updates"))
      maintainer.wait_until_succeeds(scans_command + "list | jq -e '[.data.scans[] | select(.state == \"queued\")] | length == 1'")
      update_scan = next(scan for scan in json.loads(maintainer.succeed(scans_command + "list"))["data"]["scans"] if scan["state"] == "queued")
      pending = json.loads(maintainer.succeed(status_command))["data"]["subjects"][0]["profiles"]
      assert pending[1]["pending"] and pending[1]["committedGeneration"] == 0, pending
      assert pending[2] == profiles[2], pending

      maintainer.succeed("systemd-run --unit=assessment-profile-security " + unit_environment + " --property=StandardOutput=file:/var/lib/assessment/profile-security.json --property=StandardError=file:/var/lib/assessment/profile-security-error.txt ${pkgs.bash}/bin/bash -c " + shlex.quote(command + "--idempotency-key fixture-profile-security"))
      maintainer.wait_until_succeeds(scans_command + "list | jq -e '[.data.scans[] | select(.state == \"queued\")] | length == 2'")
      security_scan = next(scan for scan in json.loads(maintainer.succeed(scans_command + "list"))["data"]["scans"] if scan["state"] == "queued" and scan["scanId"] != update_scan["scanId"])
      pending = json.loads(maintainer.succeed(status_command))["data"]["subjects"][0]["profiles"]
      assert pending[1]["pending"] and pending[2]["pending"], pending
      assert pending[2]["assessmentDigest"] == profiles[2]["assessmentDigest"], pending
      maintainer.succeed("touch /var/lib/assessment/profile-release")
      update_receipt = json.loads(maintainer.succeed(scans_command + "wait " + update_scan["scanId"] + " --timeout 60"))["data"]
      security_receipt = json.loads(maintainer.succeed(scans_command + "wait " + security_scan["scanId"] + " --timeout 60"))["data"]
      assert update_receipt["state"] == "partial", update_receipt
      assert security_receipt["state"] == "succeeded", security_receipt
      completed = json.loads(maintainer.succeed(status_command))["data"]["subjects"][0]["profiles"]
      assert completed[1]["committedGeneration"] == update_receipt["generation"], completed
      assert completed[2]["committedGeneration"] == security_receipt["generation"], completed
      assert completed[1]["assessmentDigest"] == update_receipt["assessmentDigest"] and not completed[1]["fresh"], completed
      assert completed[2]["assessmentDigest"] == security_receipt["assessmentDigest"] and completed[2]["fresh"], completed
      assert all(not profile["pending"] for profile in completed), completed

      # Start from an empty namespace so the queued jobs freeze independent
      # source closures. The highest admitted generation has update evidence
      # only; a cached vulnerability scan must recover the other profile head.
      cache_state = "/var/lib/assessment/cache-state"
      cache_repository = cache_state + "/repositories/" + namespace
      cache_lock = cache_repository + "/operation-locks/package-assessment.lock"
      maintainer.succeed("install -d -m 700 " + cache_state + " " + cache_state + "/repositories " + cache_repository + " " + cache_repository + "/operation-locks")
      maintainer.succeed("install -m 600 /dev/null " + cache_lock)
      maintainer.succeed("aos-release-fleet-fixture assessment-input 1.2.0 > /var/lib/assessment/cache-security-input.json")
      maintainer.succeed("jq 'del(.advisorySnapshot) | .advisories = []' /var/lib/assessment/cache-security-input.json > /var/lib/assessment/cache-updates-input.json")
      cache_security_command = command.replace("/var/lib/assessment/state", cache_state).replace("/var/lib/assessment/input.json", "/var/lib/assessment/cache-security-input.json")
      cache_updates_command = cache_security_command.replace("--profile vulnerabilities", "--profile updates").replace("cache-security-input.json", "cache-updates-input.json")
      cache_scans = scans_command.replace("/var/lib/assessment/state", cache_state)
      maintainer.succeed("systemd-run --unit=assessment-cache-lane-fixture aos-release-fleet-fixture assessment-lane-lock " + cache_lock + " /var/lib/assessment/cache-ready /var/lib/assessment/cache-release")
      maintainer.wait_until_succeeds("test -f /var/lib/assessment/cache-ready")
      maintainer.succeed("systemd-run --unit=assessment-cache-security " + unit_environment + " --property=StandardOutput=file:/var/lib/assessment/cache-security.json --property=StandardError=file:/var/lib/assessment/cache-security-error.txt ${pkgs.bash}/bin/bash -c " + shlex.quote(cache_security_command + "--idempotency-key fixture-cache-security"))
      maintainer.wait_until_succeeds(cache_scans + "list | jq -e '[.data.scans[] | select(.state == \"queued\")] | length == 1'")
      maintainer.succeed("systemd-run --unit=assessment-cache-updates " + unit_environment + " --property=StandardOutput=file:/var/lib/assessment/cache-updates.json --property=StandardError=file:/var/lib/assessment/cache-updates-error.txt ${pkgs.bash}/bin/bash -c " + shlex.quote(cache_updates_command + "--idempotency-key fixture-cache-updates"))
      maintainer.wait_until_succeeds(cache_scans + "list | jq -e '[.data.scans[] | select(.state == \"queued\")] | length == 2'")
      cache_queued = json.loads(maintainer.succeed(cache_scans + "list"))["data"]["scans"]
      maintainer.succeed("touch /var/lib/assessment/cache-release")
      for queued in cache_queued:
          receipt = json.loads(maintainer.succeed(cache_scans + "wait " + queued["scanId"] + " --timeout 60"))["data"]
          expected = "succeeded" if receipt["request"]["profiles"] == ["vulnerabilities"] else "partial"
          assert receipt["state"] == expected, receipt
      cache_global = json.loads(maintainer.succeed("cat " + cache_repository + "/assessments/journal.json"))["head"]
      cache_input = json.loads(maintainer.succeed("cat " + cache_repository + "/assessments/input-" + cache_global["inputDigest"].removeprefix("sha256:") + ".json"))
      assert cache_input["profiles"] == ["updates"], cache_input
      cache_closure = json.loads(maintainer.succeed("cat " + cache_repository + "/assessments/data-" + cache_global["closureDigest"].removeprefix("sha256:") + ".json"))
      assert "advisorySnapshot" not in cache_closure and cache_closure["advisories"] == [], cache_closure
      reuse_command = cache_security_command.replace("cache-security-input.json", "cache-updates-input.json").replace("--offline", "--freshness cached")
      reused = json.loads(maintainer.succeed(reuse_command + "--idempotency-key fixture-cache-reuse --token-env invalid/name --nvd-key-env invalid/name"))
      assert reused["execution"]["scan"]["usage"]["providerRequests"] == 0, reused
      reused_findings = reused["data"]["subjectResults"][0]["findings"]
      assert len(reused_findings) == 1 and "CVE-2026-10001" in reused_findings[0]["advisoryIds"], reused
    '';
}
