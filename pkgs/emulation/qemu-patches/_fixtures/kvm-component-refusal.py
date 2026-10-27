"""Exercise real QEMU component refusal, without native qualification claims."""

import json
import os
import selectors
import subprocess
import sys
import time


class QmpPeer:
    """Retain one actual stopped child and bound each protocol transaction."""

    def __init__(self, executable):
        self.process = subprocess.Popen(
            [executable, "-machine", "none", "-accel", "tcg", "-S",
             "-nodefaults", "-display", "none", "-qmp", "stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        self.pending = bytearray()
        self.sequence = 0
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def read(self):
        deadline = time.monotonic() + 10
        while True:
            newline = self.pending.find(b"\n")
            if newline >= 0:
                line = self.pending[:newline]
                del self.pending[:newline + 1]
                return json.loads(line)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise RuntimeError("actual QMP child exceeded its response allowance")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("actual QMP child disconnected")
            self.pending.extend(chunk)
            if len(self.pending) > 65536:
                raise RuntimeError("actual QMP response exceeded its retained bound")

    def request(self, command, arguments=None):
        self.sequence += 1
        request = {"execute": command, "id": self.sequence}
        if arguments is not None:
            request["arguments"] = arguments
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        while True:
            response = self.read()
            if "event" in response:
                continue
            if response.get("id") != self.sequence:
                raise RuntimeError("actual QMP response changed transaction identity")
            return response

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=10)
        finally:
            self.selector.close()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


def verify_refusal(executable):
    peer = QmpPeer(executable)
    try:
        assert "QMP" in peer.read(), "actual child must send its greeting"
        assert "return" in peer.request("qmp_capabilities")
        acceleration = peer.request("query-kvm")["return"]
        assert acceleration["enabled"] is False, "fixture must actually use TCG"
        for operation in ("query", "begin", "freeze", "step"):
            response = peer.request("x-crucible-kvm-clock", {
                "operation": operation, "window-generation": 1,
                "start-ns": 0, "end-ns": 10, "stop-budget-ns": 1_000_000,
            })
            error = response.get("error")
            assert error is not None, "TCG must refuse native component control"
            assert error["class"] == "GenericError", "component must exist and genuinely refuse"
            assert "native" in error["desc"].lower()
        assert "return" in peer.request("quit")
        peer.process.wait(timeout=10)
        assert peer.process.returncode == 0
    finally:
        peer.close()


def observe_unavailable_native_device(executable):
    if os.path.exists("/dev/kvm"):
        print("/dev/kvm path present in this build namespace: access and API "
              "availability not probed; native qualification not executed")
        return
    result = subprocess.run(
        [executable, "-machine", "none", "-accel",
         "kvm,x-crucible-clock-experiment=on", "-S", "-nodefaults", "-display", "none"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert result.returncode != 0, "absent native device must fail actual launch"
    assert b"Could not access KVM kernel module" in result.stderr, result.stderr.decode()
    print("native KVM launch: operationally unavailable (/dev/kvm absent)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: kvm-component-refusal.py QEMU_X86_64 QEMU_AARCH64")
    for binary in sys.argv[1:]:
        verify_refusal(binary)
        print(f"real TCG native-component refusal: pass ({os.path.basename(binary)})")
    if sys.argv[1:]:
        observe_unavailable_native_device(sys.argv[1])
    print("native KVM clock/run/stop qualification: not executed")
