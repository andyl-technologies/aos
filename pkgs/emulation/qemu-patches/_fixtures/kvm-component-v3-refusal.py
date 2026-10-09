"""Check actual edition-three QMP/initialization refusal without KVM qualification."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys


original_path = Path(__file__).with_name("kvm-component-refusal.py")
specification = importlib.util.spec_from_file_location("original_component", original_path)
original = importlib.util.module_from_spec(specification)
specification.loader.exec_module(original)


def verify_namespaces(executable):
    """Exercise both real component handlers on one genuinely stopped TCG child."""
    peer = original.QmpPeer(executable)
    try:
        assert "QMP" in peer.read()
        assert "return" in peer.request("qmp_capabilities")
        assert peer.request("query-kvm")["return"]["enabled"] is False

        for command in ("x-crucible-kvm-clock", "x-crucible-kvm-clock-v3"):
            for operation in ("query", "begin", "freeze", "step"):
                response = peer.request(command, {
                    "operation": operation, "window-generation": 1,
                    "start-ns": 0, "end-ns": 10, "stop-budget-ns": 1_000_000,
                })
                error = response.get("error")
                assert error is not None, "TCG cannot control a native clock domain"
                assert error["class"] == "GenericError", "actual handler must exist"
                assert ("not configured" in error["desc"]
                        or "unavailable in this build" in error["desc"]), error

        assert "return" in peer.request("quit")
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()


def verify_refused_kernel_edition(executable):
    """Refuse an unsupported edition before reaching actual kernel initialization."""
    result = subprocess.run(
        [executable, "-machine", "none", "-accel",
         "kvm,x-crucible-clock-experiment=on,x-crucible-clock-kernel-edition=4",
         "-S", "-nodefaults", "-display", "none"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert result.returncode != 0
    assert b"kernel edition must be 1, ARM 2 or x86 3" in result.stderr, result.stderr.decode()


def observe_unavailable_native_device(executable):
    """Keep an actual unavailable hardware launch separate from native qualification."""
    if os.path.exists("/dev/kvm"):
        print("/dev/kvm path present in this namespace; access/API unprobed, native qualification not executed")
        return
    result = subprocess.run(
        [executable, "-machine", "none", "-accel",
         "kvm,x-crucible-clock-experiment=on,x-crucible-clock-kernel-edition=3",
         "-S", "-nodefaults", "-display", "none"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert result.returncode != 0
    assert b"Could not access KVM kernel module" in result.stderr, result.stderr.decode()
    print("edition-three native launch: EnvironmentUnavailable (/dev/kvm absent)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: kvm-component-v3-refusal.py QEMU_X86_64 QEMU_AARCH64")
    for executable in sys.argv[1:]:
        verify_namespaces(executable)
        print(f"real TCG original/v3 handler refusal: pass ({os.path.basename(executable)})")
    verify_refused_kernel_edition(sys.argv[1])
    observe_unavailable_native_device(sys.argv[1])
    print("native KVM clock/run/all-owner stop qualification: not executed")
