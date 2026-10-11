"""Exercise actual partial exit-inventory refusal without native qualification."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys


original_path = Path(__file__).with_name("kvm-component-refusal.py")
specification = importlib.util.spec_from_file_location("original_component", original_path)
original = importlib.util.module_from_spec(specification)
specification.loader.exec_module(original)


def verify_inventory_refusal(executable):
    """Query the real native handler through a genuinely stopped TCG process."""
    peer = original.QmpPeer(executable)
    try:
        assert "QMP" in peer.read()
        assert "return" in peer.request("qmp_capabilities")
        commands = peer.request("query-commands")["return"]
        inventory_commands = [command["name"] for command in commands
                              if command["name"].startswith("x-crucible-kvm-userspace")]
        assert inventory_commands == ["x-crucible-kvm-userspace-exits"]
        response = peer.request("x-crucible-kvm-userspace-exits")
        error = response.get("error")
        assert error is not None
        assert error["class"] == "GenericError", "actual source handler must exist"
        assert ("not configured" in error["desc"]
                or "unavailable in this build" in error["desc"]), error
        response = peer.request("x-crucible-kvm-userspace-exits", {"operation": "clear"})
        assert "error" in response, "read-only inventory has no completion/clear operation"
        assert "return" in peer.request("quit")
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()


def observe_unavailable_native_inventory(executable):
    """Keep actual device refusal separate from any native execution test."""
    if os.path.exists("/dev/kvm"):
        print("/dev/kvm path present in this build namespace: access and API "
              "availability not probed; native qualification not executed")
        return
    result = subprocess.run([
        executable, "-machine", "none", "-accel",
        "kvm,x-crucible-clock-experiment=on,x-crucible-clock-kernel-edition=3,x-crucible-userspace-exit-ledger=on",
        "-S", "-nodefaults", "-display", "none",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False)
    assert result.returncode != 0
    assert b"Could not access KVM kernel module" in result.stderr, result.stderr.decode()
    assert b"Property" not in result.stderr, "actual immutable inventory property must exist"
    print("actual native userspace-inventory launch: EnvironmentUnavailable (/dev/kvm absent)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: kvm-userspace-exit-refusal.py QEMU_X86_64 QEMU_AARCH64")
    for executable in sys.argv[1:]:
        verify_inventory_refusal(executable)
        print(f"actual userspace-inventory handler refusal: PASS ({os.path.basename(executable)})")
    observe_unavailable_native_inventory(sys.argv[1])
    print("native KVM userspace/device/DMA/input/output/physical-stop qualification: not executed")
