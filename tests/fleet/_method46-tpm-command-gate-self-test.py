"""Checks relay byte/descriptor mechanics; supplies no authenticated TPM proof."""

import array
from contextlib import contextmanager, ExitStack
from pathlib import Path
import runpy
import socket
import struct
import tempfile
import unittest


Method46TpmCommandGate = runpy.run_path(
    str(Path(__file__).with_name("_method46-tpm-command-gate.py")),
)["Method46TpmCommandGate"]


def exact(channel, extent):
    result = bytearray()
    while len(result) < extent:
        data = channel.recv(extent - len(result))
        if not data:
            raise EOFError("fixture channel closed")
        result.extend(data)
    return bytes(result)


def packet(command, body=b"", tag=0x8002):
    return struct.pack(">HII", tag, 10 + len(body), command) + body


@contextmanager
def fixture(edge, fragmented=False):
    with tempfile.TemporaryDirectory(prefix="method46-relay-check-") as temporary, ExitStack() as owned:
        path = Path(temporary) / "control"
        listener = owned.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        listener.settimeout(2)
        listener.bind(str(path))
        listener.listen(1)
        original = path.stat()
        with Method46TpmCommandGate(path, 0x0180A046, edge) as gate:
            guest_control = owned.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            guest_control.settimeout(2)
            guest_control.connect(str(path))
            backend_control, _address = listener.accept()
            owned.enter_context(backend_control)
            backend_control.settimeout(2)

            # Ordinary control traffic can be fragmented independently of the
            # descriptor-bearing command and must remain byte-identical.
            guest_control.sendall(struct.pack(">I", 1))
            assert exact(backend_control, 4) == struct.pack(">I", 1)
            backend_control.sendall(b"\x12\x34")
            backend_control.sendall(b"\x56\x78")
            assert exact(guest_control, 4) == b"\x12\x34\x56\x78"

            guest_data, delegated = socket.socketpair()
            owned.enter_context(guest_data)
            guest_data.settimeout(2)
            with delegated:
                command = struct.pack(">I", 0x10)
                rights = array.array("i", [delegated.fileno()])
                guest_control.sendmsg([
                    command[:2] if fragmented else command,
                ], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                if fragmented:
                    guest_control.sendall(command[2:])
            data, ancillary, flags, _address = backend_control.recvmsg(4, socket.CMSG_SPACE(4))
            assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            data += exact(backend_control, 4 - len(data))
            assert data == command
            assert len(ancillary) == 1
            level, kind, payload = ancillary[0]
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            received = array.array("i")
            received.frombytes(payload)
            assert len(received) == 1
            backend_data = owned.enter_context(socket.socket(fileno=received[0]))
            backend_data.settimeout(2)
            backend_control.sendall(b"\0" * 4)
            assert exact(guest_control, 4) == b"\0" * 4

            yield gate, guest_data, backend_data

        restored = path.stat()
        assert (restored.st_dev, restored.st_ino) == (original.st_dev, original.st_ino)
        assert not gate.backend_path.exists()
        assert all(not worker.is_alive() for worker in gate._threads)


class CommandGateTest(unittest.TestCase):
    def test_exact_before_and_after_edges_with_fragmented_descriptor_command(self):
        request = packet(0x136, struct.pack(">II", 0x0180A046, 0x0180A046) + b"encrypted-parameter")
        response = packet(0, b"encrypted-response")
        for edge in ("before-command", "after-response"):
            for fragmented in (False, True):
                with self.subTest(edge=edge, fragmented=fragmented), fixture(edge, fragmented) as channels:
                    gate, guest, backend = channels
                    gate.arm()
                    # Packet framing is independent of stream fragmentation.
                    guest.sendall(request[:7])
                    guest.sendall(request[7:])
                    if edge == "before-command":
                        gate.wait_reached(2)
                        self.assertEqual(gate.forwarded_extends, 0)
                        backend.settimeout(0.05)
                        with self.assertRaises(socket.timeout):
                            backend.recv(1)
                        backend.settimeout(2)
                        gate.release()
                    self.assertEqual(exact(backend, len(request)), request)
                    backend.sendall(response[:6])
                    backend.sendall(response[6:])
                    if edge == "after-response":
                        gate.wait_reached(2)
                        self.assertEqual(gate.forwarded_extends, 1)
                        guest.settimeout(0.05)
                        with self.assertRaises(socket.timeout):
                            guest.recv(1)
                        guest.settimeout(2)
                        gate.release()
                    self.assertEqual(exact(guest, len(response)), response)
                    self.assertEqual(gate.forwarded_extends, 1)
                    gate.assert_healthy()

    def test_unarmed_and_other_indices_pass_without_a_gate(self):
        for armed, index in ((False, 0x0180A046), (True, 0x0180A047)):
            with self.subTest(armed=armed, index=index), fixture("before-command") as channels:
                gate, guest, backend = channels
                if armed:
                    gate.arm()
                request = packet(0x136, struct.pack(">II", index, index) + b"opaque")
                response = packet(0)
                guest.sendall(request)
                self.assertEqual(exact(backend, len(request)), request)
                backend.sendall(response)
                self.assertEqual(exact(guest, len(response)), response)
                self.assertFalse(gate.reached.is_set())
                gate.assert_healthy()

    def test_close_aborts_held_bytes_and_reaps_all_workers(self):
        with fixture("before-command") as channels:
            gate, guest, backend = channels
            gate.arm()
            guest.sendall(packet(0x136, struct.pack(">II", 0x0180A046, 0x0180A046)))
            gate.wait_reached(2)
            gate.close()
            self.assertEqual(backend.recv(1), b"")
            self.assertEqual(gate.forwarded_extends, 0)
            self.assertTrue(all(not worker.is_alive() for worker in gate._threads))

    def test_backend_error_is_not_a_successful_extend_gate(self):
        with fixture("after-response") as channels:
            gate, guest, backend = channels
            gate.arm()
            request = packet(0x136, struct.pack(">II", 0x0180A046, 0x0180A046))
            guest.sendall(request)
            self.assertEqual(exact(backend, len(request)), request)
            backend.sendall(packet(0x101, tag=0x8001))
            with self.assertRaises(RuntimeError):
                gate.wait_reached(2)
            self.assertFalse(gate.reached.is_set())

    def test_bad_frame_and_short_extend_fail_promptly(self):
        for request in (struct.pack(">HII", 0x8002, 9, 0x136), packet(0x136)):
            with self.subTest(length=len(request)), fixture("before-command") as channels:
                gate, guest, backend = channels
                gate.arm()
                guest.sendall(request)
                with self.assertRaises(RuntimeError):
                    gate.wait_reached(2)
                self.assertFalse(gate.reached.is_set())
                self.assertEqual(gate.forwarded_extends, 0)

    def test_invalid_descriptor_envelope_closes_every_received_descriptor(self):
        for command, count in ((0x11, 1), (0x10, 2), (0x10, 3)):
            with self.subTest(command=command, count=count), tempfile.TemporaryDirectory(
                prefix="method46-relay-envelope-",
            ) as temporary, ExitStack() as owned:
                path = Path(temporary) / "control"
                listener = owned.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                listener.settimeout(2)
                listener.bind(str(path))
                listener.listen(1)
                with Method46TpmCommandGate(path, 0x0180A046, "before-command") as gate:
                    guest = owned.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                    guest.connect(str(path))
                    backend, _address = listener.accept()
                    owned.enter_context(backend)
                    peers, delegates = [], []
                    for _ in range(count):
                        peer, delegated = socket.socketpair()
                        owned.enter_context(peer)
                        peer.settimeout(2)
                        peers.append(peer)
                        delegates.append(delegated)
                    try:
                        rights = array.array("i", [channel.fileno() for channel in delegates])
                        guest.sendmsg([struct.pack(">I", command)], [
                            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
                        ])
                    finally:
                        for delegated in delegates:
                            delegated.close()
                    with self.assertRaises(RuntimeError):
                        gate.wait_reached(2)
                for peer in peers:
                    self.assertEqual(peer.recv(1), b"")

    def test_close_before_connection_restores_backend_and_reaps_worker(self):
        with tempfile.TemporaryDirectory(prefix="method46-relay-idle-") as temporary:
            path = Path(temporary) / "control"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                original = path.stat()
                gate = Method46TpmCommandGate(path, 0x0180A046, "before-command")
                gate.close()
                self.assertEqual(path.stat().st_ino, original.st_ino)
                self.assertTrue(all(not worker.is_alive() for worker in gate._threads))

    def test_fixed_selection_rejects_unknown_index_and_edge(self):
        with self.assertRaises(ValueError):
            Method46TpmCommandGate("unused", 0x0180A048, "before-command")
        with self.assertRaises(ValueError):
            Method46TpmCommandGate("unused", 0x0180A046, "after-command")


if __name__ == "__main__":
    unittest.main()
