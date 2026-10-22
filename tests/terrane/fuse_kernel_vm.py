"""Measures Linux FUSE backing lifetime; does not implement a Terrane exposure.

The small server speaks the Linux 7.40 UAPI directly so that these observations
do not depend on a userspace FUSE library's release or cache policy. It serves
one permanently sealed executable and a direct-I/O control of the same bytes.
"""

import errno
import fcntl
import json
import mmap
import os
import pathlib
import select
import stat
import struct
import subprocess
import sys
import threading


HEADER = struct.Struct("=IIQQIIII")
BACKING_OPEN = 0x4010E501
BACKING_CLOSE = 0x4004E502
ENABLE_VERITY = 0x40806685
MEASURE_VERITY = 0xC0046686


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(arguments, **options):
    return subprocess.run(arguments, check=True, timeout=5, **options)


class KernelProbe:
    """Owns one bounded kernel connection and its original backing descriptor."""

    def __init__(self, descriptor, backing, body):
        self.descriptor = descriptor
        self.backing = backing
        self.filesystem = os.fstatvfs(backing)
        self.body = body
        self.backing_id = None
        self.error = None
        self.connection = None
        self.stopped = threading.Event()
        self.ready = threading.Event()
        self.reads = {2: 0, 3: 0}
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def reply(self, unique, body=b"", error=0):
        message = struct.pack("=IiQ", 16 + len(body), -error, unique) + body
        require(os.write(self.descriptor, message) == len(message), "short FUSE reply")

    def attributes(self, inode):
        directory = inode == 1
        mode = (stat.S_IFDIR | 0o555) if directory else (stat.S_IFREG | 0o555)
        return struct.pack("=6Q10I", inode, 0 if directory else len(self.body),
                           0, 0, 0, 0, 0, 0, 0, mode, 2 if directory else 1,
                           0, 0, 0, 4096, 0)

    def dispatch(self, opcode, unique, inode, body):
        if opcode == 26:  # INIT
            major, minor, _, flags = struct.unpack_from("=4I", body)
            require(major == 7 and minor >= 40 and flags & (1 << 30),
                    "kernel lacks extended FUSE 7.40 negotiation")
            require(struct.unpack_from("=I", body, 16)[0] & (1 << 5),
                    "kernel does not advertise FUSE passthrough")
            response = bytearray(64)
            struct.pack_into("=4I", response, 0, 7, 40, 0, 1 << 30)
            struct.pack_into("=HHII", response, 16, 8, 4, 131072, 1)
            # A single stacking level leaves space for an overlay above FUSE.
            struct.pack_into("=II", response, 32, 1 << 5, 1)
            self.reply(unique, response)
            self.ready.set()
        elif opcode == 1:  # LOOKUP
            target = {b"true\0": 2, b"control\0": 3}.get(body)
            if inode != 1 or target is None:
                self.reply(unique, error=errno.ENOENT)
            else:
                entry = struct.pack("=4Q2I", target, 1, 0, 0, 0, 0)
                self.reply(unique, entry + self.attributes(target))
        elif opcode == 3:  # GETATTR
            self.reply(unique, struct.pack("=QII", 0, 0, 0) + self.attributes(inode))
        elif opcode == 14:  # OPEN
            if inode == 2:
                if self.backing_id is None:
                    request = bytearray(struct.pack("=iIQ", self.backing, 0, 0))
                    self.backing_id = fcntl.ioctl(self.descriptor, BACKING_OPEN, request)
                    require(self.backing_id > 0, "kernel returned an invalid backing ID")
                    os.close(self.backing)
                    self.backing = None
                self.reply(unique, struct.pack("=QIi", 2, 1 << 7, self.backing_id))
            elif inode == 3:
                self.reply(unique, struct.pack("=QIi", 3, 1, 0))
            else:
                self.reply(unique, error=errno.EISDIR)
        elif opcode == 15:  # READ: passthrough must never arrive here.
            require(inode == 3, "passthrough unexpectedly requested userspace data")
            _, offset, length = struct.unpack_from("=QQI", body)
            self.reads[inode] += 1
            self.reply(unique, self.body[offset:offset + length])
        elif opcode in {18, 25, 34, 38}:  # RELEASE, FLUSH, ACCESS, DESTROY
            self.reply(unique)
        elif opcode in {2, 42}:  # FORGET and BATCH_FORGET have no reply.
            pass
        elif opcode == 22:  # GETXATTR
            self.reply(unique, error=errno.ENODATA)
        elif opcode == 17:  # STATFS: overlay checks its actual lower filesystem.
            info = self.filesystem
            self.reply(unique, struct.pack("=5Q10I", info.f_blocks, info.f_bfree,
                                          info.f_bavail, info.f_files, info.f_ffree,
                                          info.f_bsize, info.f_namemax,
                                          info.f_frsize, 0, *([0] * 6)))
        else:
            self.reply(unique, error=errno.ENOSYS)

    def serve(self):
        try:
            while not self.stopped.is_set():
                if not select.select([self.descriptor], [], [], 0.1)[0]:
                    continue
                request = os.read(self.descriptor, 262144)
                require(len(request) >= HEADER.size, "short FUSE request")
                length, opcode, unique, inode, *_ = HEADER.unpack_from(request)
                require(length == len(request), "invalid FUSE request length")
                self.dispatch(opcode, unique, inode, request[HEADER.size:])
        except OSError as error:
            if error.errno not in {errno.ENODEV, errno.ECONNABORTED}:
                self.error = error
        except Exception as error:
            self.error = error
        if self.error is not None:
            print(f"FUSE server failure: {self.error!r}", flush=True)
            if self.connection is not None:
                (self.connection / "abort").write_text("1\n")

    def check(self):
        if self.error is not None:
            raise self.error

    def close(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)
        require(not self.thread.is_alive(), "FUSE server did not stop")
        if self.backing is not None:
            os.close(self.backing)
        os.close(self.descriptor)


def expect_disconnected(action):
    try:
        result = action()
    except OSError as error:
        require(error.errno == errno.ENOTCONN, f"unexpected abort error: {error}")
    else:
        if isinstance(result, int):
            os.close(result)
        raise RuntimeError("disconnected userspace operation unexpectedly succeeded")


def run(root, executable):
    body = executable.read_bytes()
    require(body.startswith(b"\x7fELF"), "probe executable is not an actual ELF")
    backing_path = root / "sealed"
    with backing_path.open("xb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    backing_path.chmod(0o555)
    backing = os.open(backing_path, os.O_RDONLY | os.O_CLOEXEC)
    argument = bytearray(128)
    struct.pack_into("=4I", argument, 0, 1, 1, 4096, 0)
    fcntl.ioctl(backing, ENABLE_VERITY, argument)
    measurement = bytearray(68)
    struct.pack_into("=HH", measurement, 0, 0, 64)
    fcntl.ioctl(backing, MEASURE_VERITY, measurement)
    require(struct.unpack_from("=HH", measurement) == (1, 32), "invalid fs-verity seal")

    mountpoint, merged = root / "lower", root / "merged"
    upper, work = root / "upper", root / "work"
    for path in [mountpoint, merged, upper, work]:
        path.mkdir()
    descriptor = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
    probe = KernelProbe(descriptor, backing, body)
    mounted = False
    overlay_mounted = False
    opened = []
    mapping = None
    connection = None
    try:
        connections = pathlib.Path("/sys/fs/fuse/connections")
        before = set(connections.iterdir())
        options = f"fd={descriptor},rootmode=40000,user_id=0,group_id=0,default_permissions,ro,nosuid,nodev"
        command(["mount", "-i", "-t", "fuse", "-o", options,
                 "terrane-kernel-probe", str(mountpoint)], pass_fds=(descriptor,))
        mounted = True
        created = set(connections.iterdir()) - before
        require(len(created) == 1, "cannot identify the actual new FUSE connection")
        connection = created.pop()
        probe.connection = connection
        # Before mount, reading /dev/fuse returns ENODEV and would terminate
        # the server before the kernel can send its first INIT request.
        probe.thread.start()
        initialized = probe.ready.wait(2)
        probe.check()
        require(initialized, "FUSE INIT did not finish")
        print("PROBE negotiated FUSE passthrough", flush=True)

        for name in ["true", "control"]:
            opened.append(os.open(mountpoint / name, os.O_RDONLY | os.O_CLOEXEC))
            require(os.pread(opened[-1], len(body), 0) == body, "incorrect mounted file bytes")
        require(probe.backing is None and probe.reads[2] == 0 and probe.reads[3] > 0,
                "data did not use the intended kernel and userspace paths")
        mapping = mmap.mmap(opened[0], len(body), access=mmap.ACCESS_READ)
        require(mapping[:] == body, "incorrect passthrough mmap bytes")
        print("PROBE mounted reads and mapping verified", flush=True)
        command(["mount", "-t", "overlay", "-o",
                 f"lowerdir={mountpoint},upperdir={upper},workdir={work},nosuid,nodev",
                 "terrane-kernel-overlay", str(merged)])
        overlay_mounted = True
        print("PROBE overlay mounted", flush=True)
        # execve may need this Python server before completing. Spawn a regular
        # executable first so Python's vfork cannot suspend its own FUSE server.
        command(["env", "--", str(merged / "true")])
        print("PASS actual sealed FUSE passthrough, immediate worker FD close, mmap and exec through overlay", flush=True)

        require(fcntl.ioctl(descriptor, BACKING_CLOSE,
                            bytearray(struct.pack("=I", probe.backing_id))) == 0,
                "kernel refused backing ID release")
        require(os.pread(opened[0], len(body), 0) == body,
                "backing ID release unexpectedly revoked an existing open")
        (connection / "abort").write_text("1\n")
        expect_disconnected(lambda: os.pread(opened[1], 1, 0))
        expect_disconnected(lambda: os.open(mountpoint / "after-abort", os.O_RDONLY))
        require(os.pread(opened[0], len(body), 0) == body and mapping[:] == body,
                "unexpected change to retained passthrough backing after abort")
        probe.check()
        print("OBSERVED " + json.dumps({
            "kernel": os.uname().release,
            "backing_inode": backing_path.stat().st_ino,
            "backing_bytes": len(body),
            "backing_verity_sha256": measurement[4:36].hex(),
            "backing_id_closed": True,
            "abort_new_lookup_errno": errno.ENOTCONN,
            "abort_direct_read_errno": errno.ENOTCONN,
            "abort_existing_passthrough_readable": True,
            "abort_existing_mapping_readable": True,
            "passthrough_userspace_reads": probe.reads[2],
        }, sort_keys=True), flush=True)
    finally:
        if connection is not None and (connection / "abort").exists():
            (connection / "abort").write_text("1\n")
        if mapping is not None:
            mapping.close()
        for handle in opened:
            try:
                os.close(handle)
            except OSError as error:
                # close still closes the descriptor when its final FUSE flush
                # reports the already aborted connection.
                if error.errno != errno.ENOTCONN:
                    raise
        try:
            if overlay_mounted:
                command(["umount", str(merged)])
        finally:
            try:
                if mounted:
                    command(["umount", str(mountpoint)])
            finally:
                probe.close()
    probe.check()


if __name__ == "__main__":
    run(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
