"""Exercise actual source-built original-window QMP refusal on both ISAs.

No KVM ioctl, guest entry or whole-node qualification is represented by this
component test. The actual stopped TCG child must expose each namespace and
refuse every native-only operation without changing its run state.
"""

import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def verify(binary, helper):
    peer = helper.QmpPeer(binary)
    try:
        assert "QMP" in peer.read()
        assert "return" in peer.request("qmp_capabilities")
        assert peer.request("query-kvm")["return"]["enabled"] is False
        original_status = peer.request("query-status")["return"]
        assert original_status["running"] is False

        operations = []
        for operation in ("query", "begin", "close"):
            operations.append(("x-crucible-kvm-original-window", {
                "operation": operation,
                "generation": 1,
                "start-ns": 0,
                "end-ns": 10 if operation == "begin" else 0,
                "stop-budget-ns": 1000000 if operation == "close" else 0,
            }))
        for operation in ("query", "ack"):
            operations.append(("x-crucible-kvm-original-return", {
                "operation": operation,
                "record-index": 0,
                "generation": 1,
                "expected-invocation": 1,
            }))

        for command, arguments in operations:
            response = peer.request(command, arguments)
            error = response.get("error")
            assert error is not None, response
            assert error["class"] == "GenericError", response
            assert "native" in error["desc"].lower(), response
            assert peer.request("query-status")["return"] == original_status

        assert "return" in peer.request("quit")
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()

    print("actual original-window/return TCG refusal: pass (" +
          Path(binary).name + ")")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: refusal.py QEMU_X86 QEMU_ARM COMPONENT_HELPER")
    spec = importlib.util.spec_from_file_location("component", sys.argv[3])
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    for binary in sys.argv[1:3]:
        verify(binary, helper)
    helper.observe_unavailable_native_device(sys.argv[1])
    print("original native-window hardware/full-node qualification: not executed")
