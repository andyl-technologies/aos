"""Pauses one real initial NV Extend at the host's swtpm transport boundary.

The relay forwards the existing QEMU control channel and substitutes only the
socket passed by CMD_SET_DATAFD. It neither edits TPM packets nor supplies TPM
observations to a guest. A reached gate is a scheduling observation; independent
checks of the retained disk and authenticated TPM state must establish recovery.
"""

import array
from pathlib import Path
import socket
import struct
import threading
import time


class Method46TpmCommandGate:
    """Owns one test-only relay around a running harness-owned swtpm socket."""

    def __init__(self, control_path, index, edge):
        if index not in (0x0180A046, 0x0180A047):
            raise ValueError("gate requires a fixed initial floor index")
        if edge not in ("before-command", "after-response"):
            raise ValueError("unknown initial Extend gate edge")

        self.control_path = Path(control_path)
        self.backend_path = self.control_path.with_name(self.control_path.name + ".method46-backend")
        self.index = index
        self.edge = edge
        self.reached = threading.Event()
        self._armed = threading.Event()
        self._released = threading.Event()
        self._closed = threading.Event()
        self._lock = threading.Lock()
        self._sockets = []
        self._threads = []
        self._errors = []
        self.forwarded_extends = 0
        self._data_installed = False
        self._renamed = False
        self._listener = None
        self._listener_identity = None
        original = self.control_path.stat()
        self._backend_identity = (original.st_dev, original.st_ino)

        if self.backend_path.exists():
            raise FileExistsError(self.backend_path)
        try:
            self.control_path.rename(self.backend_path)
            self._renamed = True
            self._listener = self._own(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
            self._listener.bind(str(self.control_path))
            identity = self.control_path.stat()
            self._listener_identity = (identity.st_dev, identity.st_ino)
            self._listener.listen(1)
            self._spawn(self._control)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()

    def _own(self, channel):
        channel.settimeout(0.2)
        with self._lock:
            if self._closed.is_set():
                channel.close()
                raise EOFError("TPM relay stopped")
            self._sockets.append(channel)
        return channel

    def _spawn(self, action, *arguments):
        def worker():
            try:
                action(*arguments)
            except BaseException as error:
                if not self._closed.is_set():
                    with self._lock:
                        self._errors.append(error)

        thread = threading.Thread(target=worker, name="method46-tpm-gate")
        with self._lock:
            if self._closed.is_set():
                raise EOFError("TPM relay stopped")
            self._threads.append(thread)
            thread.start()

    def assert_healthy(self):
        """Surfaces a relay failure without printing TPM packet contents."""
        with self._lock:
            error = self._errors[0] if self._errors else None
        if error is not None:
            raise RuntimeError("initial TPM command relay failed") from error

    def arm(self):
        """Arms exactly one gate before starting the installed producer."""
        self.assert_healthy()
        if self._closed.is_set() or self._armed.is_set():
            raise RuntimeError("initial TPM command gate cannot be rearmed")
        self._armed.set()

    def wait_reached(self, timeout):
        """Waits for the selected edge, surfacing transport failure promptly."""
        deadline = time.monotonic() + timeout
        while not self.reached.wait(0.02):
            self.assert_healthy()
            if self._closed.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("initial TPM command gate was not reached")
        self.assert_healthy()

    def release(self):
        """Resumes the held bytes for relay checks that do not cut VM power."""
        if not self.reached.is_set() or self._closed.is_set():
            raise RuntimeError("no live initial TPM command gate to release")
        self._released.set()

    def _receive(self, channel, extent):
        while not self._closed.is_set():
            try:
                data = channel.recv(extent)
            except socket.timeout:
                continue
            if not data:
                raise EOFError("TPM relay channel closed")
            return data
        raise EOFError("TPM relay stopped")

    def _exact(self, channel, extent):
        result = bytearray()
        while len(result) < extent:
            result.extend(self._receive(channel, extent - len(result)))
        return bytes(result)

    def _packet(self, channel):
        header = self._exact(channel, 10)
        tag, extent, _code = struct.unpack(">HII", header)
        if tag not in (0x8001, 0x8002) or not 10 <= extent <= 1024 * 1024:
            raise ValueError("invalid TPM relay frame geometry")
        return header + self._exact(channel, extent - 10)

    def _pause(self):
        self.reached.set()
        while not self._closed.is_set():
            if self._released.wait(0.02):
                if not self._closed.is_set():
                    return
        # Closing a held relay discards its in-flight bytes. In a VM power-cut
        # test, both owned processes must be killed before closing this relay.
        raise EOFError("held TPM relay stopped")

    def _data(self, guest, backend):
        while not self._closed.is_set():
            request = self._packet(guest)
            command = struct.unpack_from(">I", request, 6)[0]
            target = False
            if command == 0x00000136:
                if len(request) < 18:
                    raise ValueError("short NV Extend handle area")
                auth_handle, nv_index = struct.unpack_from(">II", request, 10)
                target = auth_handle == nv_index == self.index

            selected = target and self._armed.is_set() and not self.reached.is_set()
            if selected and self.edge == "before-command":
                self._pause()
            backend.sendall(request)
            if target:
                self.forwarded_extends += 1

            response = self._packet(backend)
            if selected and self.edge == "after-response":
                if struct.unpack_from(">I", response, 6)[0] != 0:
                    raise RuntimeError("initial NV Extend did not succeed")
                self._pause()
            guest.sendall(response)

    def _control_responses(self, backend, guest):
        while not self._closed.is_set():
            guest.sendall(self._receive(backend, 4096))

    def _control(self):
        while not self._closed.is_set():
            try:
                guest, _address = self._listener.accept()
                break
            except socket.timeout:
                continue
        else:
            return
        self._own(guest)
        backend = self._own(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        backend.connect(str(self.backend_path))
        self._spawn(self._control_responses, backend, guest)

        while not self._closed.is_set():
            try:
                data, ancillary, flags, _address = guest.recvmsg(
                    4096, socket.CMSG_SPACE(array.array("i").itemsize * 2),
                )
            except socket.timeout:
                continue
            descriptors = []
            try:
                unexpected_ancillary = False
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        rights = array.array("i")
                        rights.frombytes(payload)
                        descriptors.extend(rights)
                    else:
                        unexpected_ancillary = True
                if unexpected_ancillary:
                    raise ValueError("unexpected TPM control ancillary message")
                if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                    raise ValueError("truncated TPM control message")
                if not data:
                    raise EOFError("TPM control channel closed")
                if not descriptors:
                    backend.sendall(data)
                    continue

                # QEMU sends exactly one stream descriptor with CMD_SET_DATAFD
                # (0x10). Preserve other control traffic byte for byte.
                if len(data) < 4:
                    data += self._exact(guest, 4 - len(data))
                if data != struct.pack(">I", 0x10) or len(descriptors) != 1 or self._data_installed:
                    raise ValueError("unexpected TPM data descriptor envelope")
                self._data_installed = True
                descriptor = descriptors.pop()
                try:
                    adopted = socket.socket(fileno=descriptor)
                except BaseException:
                    socket.close(descriptor)
                    raise
                guest_data = self._own(adopted)
                relay_data, delegated = socket.socketpair()
                with delegated:
                    self._own(relay_data)
                    rights = array.array("i", [delegated.fileno()])
                    sent = backend.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                    if sent < len(data):
                        backend.sendall(data[sent:])
                self._spawn(self._data, guest_data, relay_data)
            finally:
                for descriptor in descriptors:
                    socket.close(descriptor)

    def close(self):
        """Closes all relay descriptors, reaps workers and restores socket names."""
        if self._closed.is_set():
            return
        with self._lock:
            self._closed.set()
            channels = list(self._sockets)
            workers = list(self._threads)
        for channel in channels:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            channel.close()

        deadline = time.monotonic() + 3
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        if self._renamed:
            if self.control_path.exists():
                identity = self.control_path.stat()
                if (identity.st_dev, identity.st_ino) != self._listener_identity:
                    raise RuntimeError("TPM relay control socket was replaced")
                self.control_path.unlink()
            identity = self.backend_path.stat()
            if (identity.st_dev, identity.st_ino) != self._backend_identity:
                raise RuntimeError("TPM relay backend socket was replaced")
            self.backend_path.rename(self.control_path)
            self._renamed = False
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError("initial TPM relay worker did not exit")
