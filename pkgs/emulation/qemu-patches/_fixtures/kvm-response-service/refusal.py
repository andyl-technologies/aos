"""Exercise source-built two-ISA response-service refusal without KVM qualification."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys


helper = Path(sys.argv[3])
specification = importlib.util.spec_from_file_location("original_peer", helper)
original = importlib.util.module_from_spec(specification)
specification.loader.exec_module(original)

for executable in sys.argv[1:3]:
    peer = original.QmpPeer(executable)
    try:
        assert "QMP" in peer.read()
        assert "return" in peer.request("qmp_capabilities")
        commands = peer.request("query-commands")["return"]
        assert sum(row["name"] == "x-crucible-kvm-response-service" for row in commands) == 1
        for operation in ("submit", "poll"):
            response = peer.request("x-crucible-kvm-response-service", {
                "operation": operation,
                "vcpu-index": 0,
                "completion-id": 1,
                "exit-sequence": 2,
            })
            assert response["error"]["class"] == "GenericError"
            assert ("not configured" in response["error"]["desc"]
                    or "unavailable" in response["error"]["desc"]
                    or response["error"]["desc"] == "original paused response service requires native KVM")
        assert "return" in peer.request("quit")
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()
    print("Actual original-response namespace refuses unconfigured TCG:", Path(executable).name)

if not os.path.exists("/dev/kvm"):
    result = subprocess.run([
        sys.argv[1], "-machine", "none", "-accel",
        "kvm,x-crucible-clock-experiment=on,x-crucible-clock-kernel-edition=3,"
        "x-crucible-userspace-exit-ledger=on,x-crucible-completion-only=on,"
        "x-crucible-paused-response-service=on",
        "-S", "-nodefaults", "-display", "none",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False)
    assert result.returncode != 0
    assert b"Could not access KVM kernel module" in result.stderr
    assert b"Property" not in result.stderr
    print("Actual source-built launch EnvironmentUnavailable: /dev/kvm absent; native qualification not executed")
else:
    print("/dev/kvm path present in this namespace; access/API unprobed, native qualification not executed")
