"""Measures Linux FUSE backing lifetime; does not implement a Terrane exposure.

The small server speaks the Linux 7.40 UAPI directly so that these observations
do not depend on a userspace FUSE library's release or cache policy. It serves
one permanently sealed executable and a direct-I/O control of the same bytes.
"""

import ctypes
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
PROJECT = 71


class Quota(ctypes.Structure):
    """Matches Linux's generic if_dqblk project quota UAPI."""

    _fields_ = [(name, ctypes.c_uint64) for name in (
        "block_hard", "block_soft", "current_space", "inode_hard",
        "inode_soft", "current_inodes", "block_time", "inode_time",
    )] + [("valid", ctypes.c_uint32)]


def project_quota(root, operation, value):
    """Queries the actual ext4 project through Linux's descriptor-based UAPI."""
    # The AOS glibc has no quotactl_fd wrapper. This VM runs the x86-64 UAPI;
    # refuse another architecture rather than reusing its syscall number.
    require(os.uname().machine == "x86_64", "unsupported project quota syscall ABI")
    library = ctypes.CDLL(None, use_errno=True)
    call = library.syscall
    call.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_uint,
                     ctypes.c_uint, ctypes.c_void_p]
    call.restype = ctypes.c_long
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if call(443, descriptor, (operation << 8) | 2,
                PROJECT, ctypes.byref(value)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(descriptor)
    return value


def charge(root):
    value = project_quota(root, 0x800007, Quota())
    require(value.block_hard == 8192, "project's finite quota changed")
    return value.current_space, value.current_inodes


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


def close_fuse_file(descriptor):
    try:
        os.close(descriptor)
    except OSError as error:
        # close still closes the descriptor when final FUSE flush reports
        # the already aborted connection.
        if error.errno != errno.ENOTCONN:
            raise


def unprivileged_registration(descriptor, backing):
    """Attempts the original connection ioctl after an actual capability drop."""
    status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(os.getresuid() == (848, 848, 848) and os.getresgid() == (848, 848, 848)
            and os.getgroups() == [] and status["NoNewPrivs"].strip() == "1"
            and all(int(status[name].strip(), 16) == 0
                    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
            "registration refusal actor retained privileged authority")
    device = os.fstat(descriptor)
    require(stat.S_ISCHR(device.st_mode) and device.st_rdev == os.makedev(10, 229)
            and stat.S_ISREG(os.fstat(backing).st_mode)
            and fcntl.fcntl(backing, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
            "registration refusal lacks the actual original native descriptors")
    measurement = bytearray(68)
    struct.pack_into("=HH", measurement, 0, 0, 64)
    fcntl.ioctl(backing, MEASURE_VERITY, measurement)
    require(struct.unpack_from("=HH", measurement) == (1, 32),
            "registration refusal backing lacks its actual immutable seal")
    try:
        fcntl.ioctl(descriptor, BACKING_OPEN, struct.pack("=iIQ", backing, 0, 0))
    except OSError as error:
        require(error.errno == errno.EPERM,
                "unprivileged backing registration returned another errno")
    else:
        raise RuntimeError("capability-free worker registered a passthrough backing")
    print("PASS actual unprivileged original-connection backing registration refuses EPERM before privileged registration", flush=True)


def run(root, executable):
    body = executable.read_bytes()
    require(body.startswith(b"\x7fELF"), "probe executable is not an actual ELF")
    project_quota(root, 0x800008, Quota(block_hard=8192, valid=1))
    require(charge(root) == (0, 0), "project was charged before backing creation")
    backing_path = root / "sealed"
    with backing_path.open("xb") as stream:
        # Only the backing inode belongs to this project. Overlay and mountpoint
        # allocations cannot hide or imitate its final charge release.
        attributes = bytearray(28)
        fcntl.ioctl(stream.fileno(), 0x801C581F, attributes)
        struct.pack_into("=I", attributes, 12, PROJECT)
        fcntl.ioctl(stream.fileno(), 0x401C5820, attributes)
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
    original_inode = backing_path.stat().st_ino
    original_charge = charge(root)
    require(original_charge[0] >= len(body) and original_charge[1] == 1,
            "sealed backing lacks actual project quota funding")

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
        # A separate executable drops every real capability. It borrows only
        # these original test descriptors and exits before privileged setup;
        # this diagnostic is not a production registration-broker contract.
        refused = subprocess.run([
            "setpriv", "--reuid=848", "--regid=848", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", sys.executable, __file__, "--unprivileged-registration",
            str(descriptor), str(backing)], pass_fds=(descriptor, backing),
            capture_output=True, text=True, timeout=5)
        print(refused.stdout, end="", flush=True)
        print(refused.stderr, end="", flush=True)
        require(refused.returncode == 0 and refused.stdout.splitlines() == [
            "PASS actual unprivileged original-connection backing registration refuses EPERM before privileged registration"],
            "actual unprivileged backing registration refusal witness missing")


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
        backing_path.unlink()
        require(not backing_path.exists() and charge(root) == original_charge,
                "unlink or abort prematurely released retained backing's charge")
        require(os.pread(opened[0], len(body), 0) == body and mapping[:] == body,
                "unlink changed the retained passthrough descriptor or mapping")
        close_fuse_file(opened.pop(0))
        require(mapping[:] == body and charge(root) == original_charge,
                "consumer descriptor close prematurely released mapped backing")
        probe.check()
        print("OBSERVED " + json.dumps({
            "kernel": os.uname().release,
            "backing_inode": original_inode,
            "backing_bytes": len(body),
            "backing_verity_sha256": measurement[4:36].hex(),
            "backing_id_closed": True,
            "capability_free_registration_errno": errno.EPERM,
            "abort_new_lookup_errno": errno.ENOTCONN,
            "abort_direct_read_errno": errno.ENOTCONN,
            "abort_existing_passthrough_readable": True,
            "abort_existing_mapping_readable": True,
            "closed_consumer_fd_mapping_readable": True,
            "passthrough_userspace_reads": probe.reads[2],
            "project_hard_limit_bytes": 8 * 1024 * 1024,
            "unlinked_retained_project_bytes": original_charge[0],
            "unlinked_retained_project_inodes": original_charge[1],
        }, sort_keys=True), flush=True)
    finally:
        if connection is not None and (connection / "abort").exists():
            (connection / "abort").write_text("1\n")
        if mapping is not None:
            mapping.close()
        for handle in opened:
            close_fuse_file(handle)
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
    os.sync()
    final_charge = charge(root)
    require(final_charge == (0, 0), "final kernel references retained backing charge")
    print("RELEASED " + json.dumps({"project_bytes": final_charge[0],
                                    "project_inodes": final_charge[1]},
                                   sort_keys=True), flush=True)
    print("PASS actual project quota retains unlinked sealed backing through abort and releases bytes and inode after final kernel references close", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--unprivileged-registration":
        unprivileged_registration(int(sys.argv[2]), int(sys.argv[3]))
    else:
        run(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
