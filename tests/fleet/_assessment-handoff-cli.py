# Production source-intent export and local planning with independently seeded
# fixture discovery. This does not qualify provider origin trust or Hub IAM.

import copy
import json
import os
from pathlib import Path
import subprocess
import sys

root, state, artifacts = map(Path, sys.argv[1:4])
binary, support = map(Path, sys.argv[4:6])
environment = os.environ.copy()
environment.update({
    "AOS_ROOT": str(root), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
    "XDG_CONFIG_HOME": str(artifacts / "config"), "XDG_STATE_HOME": str(artifacts / "xdg-state"),
})
for path in [root, state, artifacts]:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def command(argv, okay=True):
    result = subprocess.run(list(map(str, argv)), cwd=root, env=environment,
                            capture_output=True, text=True, timeout=60)
    assert (result.returncode == 0) == okay, (argv, result.stdout, result.stderr)
    return result


def cli(*args, okay=True):
    return command([binary, "--json", "maintain", "--state-dir", state, *args], okay)


def write(path, data):
    with path.open("x") as output:
        os.chmod(path, 0o600)
        output.write(data)


inventory = json.loads(command([support, "assessment-handoff-inventory"]).stdout)
encoded = json.dumps(json.dumps(inventory, separators=(",", ":")))
write(root / "default.nix", '{ system ? "x86_64-linux", ... }: { maintenanceInventory = builtins.fromJSON ' + encoded + '; }\n')
(root / "pkgs/test").mkdir(parents=True)
write(root / "pkgs/test/fixture.nix", "# Fixture source definition; planning does not apply its patch.\n")
command(["git", "init"])
command(["git", "remote", "add", "origin", "https://example.org/assessment-handoff-fixture.git"])
command(["git", "add", "default.nix", "pkgs/test/fixture.nix"])
command(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.org", "-c", "commit.gpgSign=false", "commit", "-m", "Fixture source base"])
base = command(["git", "rev-parse", "HEAD"]).stdout.strip()
cli("inventory")
envelopes = list(state.glob("repositories/*/inventory.json"))
assert len(envelopes) == 1, envelopes
envelope = envelopes[0]
input_path, bundle_path, intent_path = [artifacts / name for name in ["input.json", "bundle.json", "intent.json"]]
write(input_path, command([support, "assessment-handoff-input", envelope]).stdout)
discovery_path = envelope.parent / "discovery-latest.json"
discovery = command([support, "assessment-handoff-discovery", envelope]).stdout
write(discovery_path, discovery)
assert json.loads(discovery)["units"][0]["components"][0]["selected"]["upstreamId"] == "v1.4.0"
before = discovery_path.read_bytes()
scan = json.loads(cli("scan", "--profile", "updates", "--freshness", "offline", "--assessment-input", input_path,
    "--evidence-output", bundle_path, "--update-intent-subject", "subject", "--update-intent-output", intent_path).stdout)
assert scan["execution"]["scan"]["usage"]["providerRequests"] == 0
intent = json.loads(intent_path.read_text())
assert intent["components"][0]["target"]["upstreamId"] == "v1.3.0"
assert (intent_path.stat().st_mode & 0o777) == 0o600
plan_args = ["plan", "fixture-1", "--assessment-intent", intent_path, "--assessment-evidence", bundle_path]
result = json.loads(cli(*plan_args).stdout)
plan = result["data"]["plan"]
assert plan["units"][0]["componentTargets"]["main"]["upstreamId"] == "v1.3.0", plan
assert plan["units"][0]["targetPackageVersion"] == "1.3.0"
selection = envelope.parent / "discovery" / (plan["discoverySnapshotDigest"].split(":", 1)[1] + ".json")
assert json.loads(selection.read_text())["units"][0]["components"][0]["selected"]["upstreamId"] == "v1.3.0"
assert discovery_path.read_bytes() == before
assert command(["git", "rev-parse", "HEAD"]).stdout.strip() == base
assert not command(["git", "status", "--porcelain"]).stdout.strip()
assert json.loads(cli(*plan_args).stdout)["data"]["plan"]["planId"] == plan["planId"]
retained_plans = list((envelope.parent / "plans").glob("*.json"))
assert len(retained_plans) == 1

for field in ["target", "source", "expiry", "commands"]:
    changed = copy.deepcopy(intent)
    if field == "target":
        changed["components"][0]["target"]["upstreamId"] = "v1.4.0"
    elif field == "source":
        changed["sourceContentDigest"] = "sha256:" + "f" * 64
    elif field == "expiry":
        changed["validUntil"] = "2099-01-01T00:00:00Z"
    else:
        changed["argv"] = ["arbitrary-command"]
    altered = artifacts / (field + ".json")
    write(altered, json.dumps(changed))
    cli("plan", "fixture-1", "--assessment-intent", altered, "--assessment-evidence", bundle_path, okay=False)
    assert list((envelope.parent / "plans").glob("*.json")) == retained_plans

original_intent = intent_path.read_bytes()
cli("scan", "--profile", "updates", "--freshness", "offline", "--assessment-input", input_path,
    "--evidence-output", artifacts / "replacement-bundle.json",
    "--update-intent-subject", "subject", "--update-intent-output", intent_path, okay=False)
assert intent_path.read_bytes() == original_intent
(root / "pkgs/test/fixture.nix").write_text("# Changed fixture source.\n")
cli(*plan_args, okay=False)
assert discovery_path.read_bytes() == before
assert list((envelope.parent / "plans").glob("*.json")) == retained_plans
print("PASS: actual CLI exact assessment handoff, independent local discovery and stale-source refusal")
