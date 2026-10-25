"""Joins a genuine signed owner and production FUSE worker in a native guest."""

import array
from concurrent.futures import ThreadPoolExecutor
import errno
import importlib.util
import os
import socket
import stat
import struct
import subprocess
import time


BODY = b"actual scoped worker backing through serialized owner Send"


def run(support, executable, environment, source, owner_command=None, configured=False, late=False, expiry=False):
    """Mounts only the original worker device and drives authenticated serving."""
    support.require(os.geteuid() == 0, "mounted supervisor requires administration")
    specification = importlib.util.spec_from_file_location(
        "mounted_fuse_transport", source / "tests/terrane/fuse_connection_vm.py")
    transport = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(transport)
    target = support.RUNTIME / "mounted-view"
    target.mkdir()
    supervisor, owner_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    supervisor.settimeout(5)
    supervisor.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    log_path = support.RUNTIME / "mounted-owner.log"
    owner = None
    mounted = False
    retained = None
    executor = ThreadPoolExecutor(max_workers=2)
    output = []

    def receive(expected, uid=840, timeout=5):
        """Checks the original sender and descriptors within one total phase bound."""
        deadline = time.monotonic() + timeout
        for _ in range(16):
            remaining = deadline - time.monotonic()
            support.require(remaining > 0, "mounted owner control phase elapsed")
            supervisor.settimeout(remaining)
            packet, ancillary, flags, _ = supervisor.recvmsg(
                4096, socket.CMSG_SPACE(253 * 4) + socket.CMSG_SPACE(12),
                socket.MSG_CMSG_CLOEXEC)
            descriptors = []
            credentials = []
            try:
                for level, kind, data in ancillary:
                    if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        rights = array.array("i")
                        rights.frombytes(data)
                        descriptors.extend(rights)
                    elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS):
                        credentials.append(struct.unpack("3i", data))
                    else:
                        raise RuntimeError("unexpected mounted owner ancillary field")
                # Linux reports the requested CLOEXEC flag on a complete receive.
                support.require(packet and not flags & ~int(socket.MSG_CMSG_CLOEXEC)
                    and credentials == [(owner.pid, uid, uid)],
                    "mounted fixture lost its actual original owner role")
                if packet == expected:
                    support.require(all(not os.get_inheritable(fd) for fd in descriptors),
                        "mounted handoff retained an inheritable alias")
                    support.require(len(descriptors) == (1 if expected == b"DEVICE" else 0),
                        "mounted control transferred an unexpected descriptor")
                    return descriptors.pop() if descriptors else None
                support.require(not descriptors and uid == 840
                    and packet not in [b"DEVICE", b"PREPARED", b"READY", b"FETCH", b"EXPIRED", b"DRAINED"],
                    "mounted owner control lost its original ordering")
                output.append(packet)
                support.require(sum(map(len, output)) <= 4096,
                    "mounted owner output exceeds its finite protocol")
                print(packet.decode(), end="", flush=True)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
        raise RuntimeError("mounted owner never reached its expected control")

    try:
        with log_path.open("wb") as log:
            owner = subprocess.Popen(owner_command or [executable, "worker-mounted"], env=environment,
                stdout=owner_socket, stderr=log, close_fds=True)
            owner_socket.close()
            device = receive(b"DEVICE", uid=0)
            try:
                observed = os.fstat(device)
                support.require(stat.S_ISCHR(observed.st_mode)
                    and observed.st_rdev == os.makedev(10, 229),
                    "original worker did not supply the actual FUSE device")
                transport.mount(device, target)
                mounted = True
            finally:
                os.close(device)
            support.require(supervisor.send(b"M") == 1, "mount acknowledgement truncated")
            # The child already bounds public-context provisioning at thirty
            # seconds. Repository initialization, signed commits and native
            # admission precede worker startup; READY retains its five-second
            # exchange bound once that real provisioning is complete.
            receive(b"PREPARED", timeout=30)
            receive(b"READY")

            first = executor.submit(transport.read_file, target / "file")
            second = executor.submit(transport.read_file, target / "file")
            receive(b"FETCH")
            support.require((target / "file").stat().st_size == len(BODY)
                and stat.S_ISDIR(target.stat().st_mode),
                "actual scoped fetch blocked production kernel metadata")
            if late:
                for opening in [first, second]:
                    try:
                        opening.result(timeout=6)
                    except OSError as error:
                        support.require(error.errno == errno.EIO,
                            "expired configured cold open returned another errno")
                    else:
                        raise RuntimeError("withheld configured cold open escaped its deadline")
                receive(b"EXPIRED")
                first = executor.submit(transport.read_file, target / "file")
                second = first
            support.require(supervisor.send(b"G") == 1, "grant acknowledgement truncated")
            expected = (BODY[:1], BODY[1:], BODY[2:10], BODY[3:11])
            support.require(first.result(timeout=5) == second.result(timeout=5) == expected,
                "signed-root production reads changed the actual verified backing")
            retained = (target / "file").open("rb", buffering=0)
            support.require(retained.read() == BODY,
                "repeated production open lost the original verified backing")
            os.fsync(retained.fileno())

            support.require(supervisor.send(b"D") == 1, "drain acknowledgement truncated")
            receive(b"DRAINED", timeout=25 if expiry else 5)
            try:
                target.stat()
            except OSError as error:
                support.require(error.errno == errno.ENOTCONN,
                    "durably drained production mount returned another errno")
            else:
                raise RuntimeError("drained production worker still serves metadata")
            try:
                retained.close()
            except OSError as error:
                # Fallback FLUSH needs the disconnected worker even though the
                # kernel still releases this original descriptor on close.
                support.require(error.errno == errno.ENOTCONN and retained.closed,
                    "drained backing close lost its original release semantics")
            retained = None
            transport.unmount(target)
            mounted = False
            support.require(owner.wait(timeout=5) == 0,
                "mounted signed owner did not finish its genuine checks")
            expected_witnesses = [
                ("PASS configured native owner completes actual recovery and acknowledged Resume before mounted worker startup"
                 if configured else "PASS surface admission requires actual recovery and acknowledged Resume"),
                "PASS actual signed-owner index and verified backing serve coalesced kernel opens through the production worker",
                "PASS durable drain stops the mounted production worker while retaining original physical bindings and pins"]
            if configured:
                expected_witnesses.append("PASS configured production worker opens fetch and seal original signed cold backing through retained service before kernel reads")
            if late:
                expected_witnesses.append("PASS actual kernel open deadlines return EIO while original configured cold work survives and a later open joins the same fetch before sealed handoff")
            if expiry:
                expected_witnesses.append("PASS actual durable exposure expiry autonomously drains retained service and disconnects idle mounted worker while preserving original kernel backing custody")
            support.require(b"".join(output).decode().splitlines() == expected_witnesses,
                "mounted owner omitted its original authority or custody checks")
            print("PASS mounted production worker joins signed index startup, coalesced verified reads, responsive metadata and durable drain", flush=True)
    finally:
        if retained is not None:
            retained.close()
        supervisor.close()
        owner_socket.close()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait(timeout=5)
        if mounted:
            transport.unmount(target)
        executor.shutdown(wait=True)
        target.rmdir()
        if log_path.exists():
            print(log_path.read_text(), end="", flush=True)
