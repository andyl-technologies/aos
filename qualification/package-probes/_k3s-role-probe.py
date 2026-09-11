"""Exercises staged role configuration without replacing fleet workload proof."""

import json
import os
from pathlib import Path
import subprocess
import sys


package, mode = sys.argv[1:]
roles = {
    "k3s-combined": "combined",
    "k3s-control-plane": "control-plane",
    "k3s-worker": "worker",
}
if package not in roles or mode not in {"primary", "bad-input"}:
    raise RuntimeError("unexpected role probe request")

outputs = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_OUTPUTS"])
# This evaluator is supplied by the package executor, never host PATH or a
# package dependency added only to make its qualification easier.
nix_store = Path(os.environ["AOS_QUALIFICATION_NIX_STORE"])
if not str(nix_store).startswith("/nix/store/") or nix_store.name != "nix-store":
    raise RuntimeError("role probe lacks its immutable executor evaluator")
evaluator = nix_store.with_name("nix-instantiate")

command = [str(evaluator), "--store", "dummy://", "--eval", "--strict", "--json", "role.nix"]
for name, value in {
    "baseRoot": outputs["configuration-base"],
    "configRoot": outputs["config"],
    "outputRoot": outputs["out"],
    "package": package,
    "mode": mode,
}.items():
    command.extend(["--argstr", name, value])
result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=180)

if mode == "bad-input":
    expected = (
        "k3s.serverUrl is required for the worker role"
        if package == "k3s-worker"
        else "k3s.token must reference a credential when k3s is enabled"
    )
    if result.returncode == 0 or expected not in result.stderr:
        raise RuntimeError(f"role did not reject its invalid input: {result.stdout}\n{result.stderr}")
    print("invalid role configuration rejected")
else:
    if result.returncode != 0:
        raise RuntimeError(f"valid role configuration failed: {result.stderr}")
    observed = json.loads(result.stdout)
    environment = observed["environment"]
    expected_values = {
        "K3S_ENABLED": "true",
        "K3S_NODE_NAME": "qualification-node",
        "K3S_NODE_LABEL": "aos.example/role=qualified",
    }
    if any(environment.get(name) != value for name, value in expected_values.items()):
        raise RuntimeError("role module rendered incorrect service configuration")
    if package == "k3s-worker":
        if environment.get("K3S_URL") != "https://control.example:6443":
            raise RuntimeError("worker module lost its control-plane endpoint")
    elif "K3S_URL" in environment:
        raise RuntimeError("standalone server role unexpectedly joins another server")
    if (
        observed["role"] != roles[package]
        or observed["credential"] != "system-credential:k3s-qualification-token"
        or observed["resourceSchema"] != "aos.kubernetes-resources/v1"
    ):
        raise RuntimeError("role module changed its role, credential or resource contract")
    print("role configuration rendered and bound")
