"""Qualifies original Rust FUSE device exchanges in a disposable native VM."""

import array
from concurrent.futures import ThreadPoolExecutor
import ctypes
import errno
import fcntl
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import time
from threading import Event


def require(condition, message):
    """Rejects a failed actual kernel or custody observation."""
    if not condition:
        raise RuntimeError(message)


def mount(device, target):
    """Mounts the original device without issuing incidental filesystem reads."""
    library = ctypes.CDLL(None, use_errno=True)
    library.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_ulong, ctypes.c_char_p]
    library.mount.restype = ctypes.c_int
    options = f"fd={device},rootmode=40000,user_id=0,group_id=0,max_read=131072"
    if library.mount(b"terrane-transport-fixture", os.fsencode(target), b"fuse",
                     1 | 2 | 4, options.encode()) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def unmount(target):
    """Removes the owned mount after its worker disconnects or serves unmount."""
    subprocess.run(["umount", str(target)], check=True, timeout=5)


def grant_backing(channel, descriptor, worker_pid, release, sequence=1, path=b"a", received=None):
    """Returns one original sealed fixture inode over the actual private channel."""
    packet, ancillary, flags, _ = channel.recvmsg(4172, socket.CMSG_SPACE(12))
    require(not flags and len(ancillary) == 1
            and ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
            and struct.unpack("3i", ancillary[0][2]) == (worker_pid, 840, 840),
            "backing request lost its original worker credentials")
    require(len(packet) == 76 + len(path) and packet[:8] == b"TBC1\x02\0\0\0"
            and packet[8:24] == bytes.fromhex("0123456789abcdef0123456789abcdef")
            and packet[24:40] == struct.pack("<QQ", 1, sequence)
            and packet[72:] == struct.pack("<I", len(path)) + path,
            "kernel open requested a foreign fixture selection")
    if received is not None:
        received.set()
    require(release.wait(5), "concurrent kernel opens never joined the original handoff")
    require(channel.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                        array.array("i", [descriptor]))]) == len(packet),
            "actual sealed backing reply was truncated")
    return os.fstat(descriptor)


def read_file(path):
    """Owns one actual kernel open through checked ranges and closure."""
    with path.open("rb", buffering=0) as file:
        return (file.read(1), file.read(), os.pread(file.fileno(), 8, 2),
                os.pread(file.fileno(), 8, 3))


def scenario(executable, directory, mode):
    """Transfers one mount alias, then observes the worker's sole original fd."""
    target = directory / mode
    target.mkdir()
    supervisor, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    supervisor.settimeout(5)
    backing_server, backing_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    backing_server.settimeout(5)
    backing_server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child = None
    mounted = False
    descriptors = []
    backing = None
    executor = None
    release = None
    try:
        child = subprocess.Popen([
            "setpriv", "--reuid=840", "--regid=840", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", str(executable), mode,
        ], stdin=backing_child if mode in {"read", "late", "multi"} else subprocess.DEVNULL,
            stdout=child_socket, stderr=subprocess.PIPE,
            close_fds=True)
        child_socket.close()
        backing_child.close()
        message, ancillary, flags, _ = supervisor.recvmsg(
            64, socket.CMSG_SPACE(array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC)
        for level, kind, data in ancillary:
            require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
                    "unexpected worker ancillary message")
            received = array.array("i")
            received.frombytes(data)
            descriptors.extend(received)
        require(message == b"DEVICE" and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                and len(descriptors) == 1, "worker did not transfer exactly one device alias")
        observed = os.fstat(descriptors[0])
        require(stat.S_ISCHR(observed.st_mode) and observed.st_rdev == os.makedev(10, 229),
                "worker transferred a foreign descriptor")
        mount(descriptors[0], target)
        mounted = True
        os.close(descriptors.pop())
        require(supervisor.send(b"M") == 1, "mount-ready message was truncated")
        require(supervisor.recv(64) == b"READY", "actual kernel INIT did not complete")

        if mode in {"serve", "metadata", "read", "late", "multi", "large", "readiness"}:
            metadata = target.stat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o7777 == 0o555
                    and metadata.st_ino == 16
                    and metadata.st_nlink == (2 if mode in {"serve", "readiness"} else 3)
                    and (metadata.st_uid, metadata.st_gid) == (0, 0)
                    and metadata.st_atime_ns == 1_000_000_000
                    and metadata.st_mtime_ns == 1_000_000_000
                    and metadata.st_ctime_ns == 1_000_000_000,
                    "actual GETATTR reply differs from fixture root")
            if mode in {"serve", "readiness"}:
                require(os.listdir(target) == [], "actual READDIR reply was not empty")
                try:
                    os.getxattr(target, b"user.note")
                except OSError as error:
                    require(error.errno == errno.EOPNOTSUPP,
                            "disabled xattr presentation returned the wrong errno")
                else:
                    raise RuntimeError("disabled exposure served an extended attribute")
            else:
                original = os.fsencode(target)
                if mode != "large":
                    require(sorted(os.listdir(original)) == [b"a", b"b", b"directory", b"link", b"\xff"],
                            "actual READDIR lost original direct-child names")
                left, right = (target / "a").stat(), (target / "b").stat()
                require(left.st_ino == right.st_ino and left.st_nlink == right.st_nlink == 2
                        and left.st_size == right.st_size == 3
                        and (left.st_uid, left.st_gid) == (right.st_uid, right.st_gid) == (42, 43)
                        and left.st_mode & 0o7777 == right.st_mode & 0o7777 == 0o640,
                        "actual LOOKUP/GETATTR lost original hard-link identity or attributes")
                unrelated = os.stat(original + b"/\xff")
                require(unrelated.st_ino != left.st_ino and unrelated.st_nlink == 1,
                        "equal file content aliased an unrelated namespace inode")
                file = original + b"/a"
                require(sorted(map(os.fsencode, os.listxattr(file))) == [b"user.note", b"user.\xff"]
                        and os.getxattr(file, b"user.note") == b"raw\0value\xff"
                        and os.getxattr(file, b"user.\xff") == b"",
                        "actual xattr size probes or values changed recorded bytes")
                for name in [b"security.capability", b"system.posix_acl_access", b"trusted.overlay", b"user.absent"]:
                    try:
                        os.getxattr(file, name)
                    except OSError as error:
                        require(error.errno == errno.ENODATA,
                                "hidden or absent xattr returned the wrong errno")
                    else:
                        raise RuntimeError("hidden or absent xattr was disclosed")
                library = ctypes.CDLL(None, use_errno=True)
                library.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                            ctypes.c_void_p, ctypes.c_size_t]
                library.getxattr.restype = ctypes.c_ssize_t
                small = ctypes.create_string_buffer(1)
                require(library.getxattr(file, b"user.note", small, 1) == -1
                        and ctypes.get_errno() == errno.ERANGE,
                        "actual short xattr request did not return ERANGE")
                try:
                    os.setxattr(file, b"user.note", b"changed")
                except OSError as error:
                    require(error.errno == errno.EROFS,
                            "actual lower mount allowed extended attribute mutation")
                else:
                    raise RuntimeError("read-only FUSE lower allowed xattr mutation")
                require(os.listdir(target / "directory") == ["file"]
                        and (target / "directory/file").stat().st_ino != left.st_ino,
                        "nested READDIR or reverse GETATTR escaped its original parent")
                require(os.readlink(original + b"/link") == b"./directory/../a\xff"
                        and (target / "link").lstat().st_size == len(b"./directory/../a\xff"),
                        "actual READLINK normalized or decoded original symlink bytes")
                if mode in {"read", "late", "multi"}:
                    source = directory / "backing" / ("original-" + mode)
                    with source.open("xb") as output:
                        output.write(b"abc")
                        output.flush()
                        os.fsync(output.fileno())
                    backing = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
                    # Native Linux fsverity_enable_arg requires an explicit Merkle
                    # block size. Match the private ext4 filesystem and AOS helper.
                    argument = struct.pack("=III", 1, 1, 4096) + bytes(116)
                    fcntl.ioctl(backing, 0x40806685, argument)
                    os.lseek(backing, 1, os.SEEK_SET)
                    executor = ThreadPoolExecutor(max_workers=4 if mode == "multi" else 3)
                    release = Event()
                    first_received = Event()
                    grant = executor.submit(grant_backing, backing_server, backing, child.pid,
                                            release, 1, b"a", first_received)
                    started = time.monotonic()
                    first = executor.submit(read_file, target / "a")
                    require(first_received.wait(2), "original kernel open did not submit its fetch")
                    if mode == "late":
                        try:
                            first.result(timeout=2)
                        except OSError as error:
                            require(error.errno == errno.EIO,
                                    "expired actual kernel open did not return EIO")
                        else:
                            raise RuntimeError("withheld backing satisfied an expired kernel open")
                        require(time.monotonic() - started < 2
                                and supervisor.recv(64) == b"OPEN_EXPIRED",
                                "open deadline lost its original pending fetch")
                    alias = executor.submit(read_file, target / "b")
                    require((target / "directory").stat().st_mode & 0o7777 == 0o750,
                            "pending backing blocked unrelated kernel metadata")
                    require(supervisor.recv(64) == b"COALESCED",
                            "concurrent kernel opens did not share their original handoff")
                    expected = (b"a", b"bc", b"c", b"")
                    if mode == "multi":
                        distinct = executor.submit(read_file, target / "directory" / "file")
                        require(supervisor.recv(64) == b"QUEUED_DISTINCT",
                                "distinct-node open lost its bounded backing reservation")
                        require((target / "directory").stat().st_mode & 0o7777 == 0o750,
                                "queued distinct-node open blocked kernel metadata")
                    release.set()
                    if mode == "multi":
                        grant.result(timeout=5)
                        second_release = Event()
                        second_received = Event()
                        second_grant = executor.submit(
                            grant_backing, backing_server, backing, child.pid,
                            second_release, 2, b"directory/file", second_received)
                        require(second_received.wait(2)
                                and (target / "directory").stat().st_mode & 0o7777 == 0o750,
                                "second original fetch blocked kernel metadata")
                        second_release.set()
                        require(distinct.result(timeout=5) == expected,
                                "distinct-node backing changed its original file bytes")
                        second_grant.result(timeout=5)
                    require(alias.result(timeout=5) == expected,
                            "actual FUSE fallback READ changed sealed bytes or EOF")
                    if mode in {"read", "multi"}:
                        require(first.result(timeout=5) == expected,
                                "coalesced original kernel open lost its response")
                    if mode == "read":
                        print("PASS concurrent kernel hard-link opens coalesce while metadata remains responsive", flush=True)
                    with (target / "a").open("rb", buffering=0) as reopened:
                        require(reopened.read() == b"abc",
                                "repeated original open lost the retained backing")
                    with (target / "a").open("rb", buffering=0) as first_handle:
                        with (target / "b").open("rb", buffering=0) as second_handle:
                            require(first_handle.read(1) == second_handle.read(1) == b"a",
                                    "independent live handles did not retain their own cursors")
                        # Require another actual FUSE READ on the surviving fh,
                        # rather than satisfying this assertion from KEEP_CACHE.
                        os.posix_fadvise(first_handle.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                        require(first_handle.read() == b"bc",
                                "closing one hard-link handle invalidated another live handle")
                    if mode == "read":
                        print("PASS original kernel handles survive peer RELEASE and repeated opens", flush=True)
                    original_stat = grant.result(timeout=5)
                    require((original_stat.st_dev, original_stat.st_ino)
                            == (os.fstat(backing).st_dev, os.fstat(backing).st_ino)
                            and os.lseek(backing, 0, os.SEEK_CUR) == 1,
                            "FUSE fallback changed the original backing or shared cursor")
                    backing_server.setblocking(False)
                    try:
                        unexpected = backing_server.recv(4172)
                    except BlockingIOError:
                        pass
                    else:
                        require(not unexpected, "kernel opens fetched an unexpected additional backing")
                    if mode == "read":
                        print("PASS actual kernel FUSE READ uses one original sealed grant for repeated hard-link opens with unchanged backing cursor", flush=True)
                    if mode == "multi":
                        print("PASS distinct kernel inodes queue separate original fetches while hardlinks coalesce and metadata remains responsive", flush=True)
                    if mode == "late":
                        print("PASS expired kernel open returns EIO while its original fetch survives for a later hard-link open and retained reads", flush=True)
            try:
                (target / "absent").stat()
            except OSError as error:
                require(error.errno == errno.ENOENT, "actual LOOKUP lost its errno")
            else:
                raise RuntimeError("missing fixture path unexpectedly exists")
            unmount(target)
            mounted = False
            require(supervisor.send(b"U") == 1, "unmount acknowledgement was truncated")
            require(supervisor.recv(64) == b"STOPPED", "worker failed explicit post-unmount close")
        else:
            require(supervisor.recv(64) == b"CLOSED", "failed receive did not close its device")
            try:
                target.stat()
            except OSError as error:
                require(error.errno == errno.ENOTCONN,
                        "last descriptor close did not disconnect actual kernel worker traffic")
            else:
                raise RuntimeError("closed device connection unexpectedly serves metadata")
        require(child.wait(timeout=5) == 0,
                "actual confined FUSE actor failed: " + child.stderr.read().decode(errors="replace"))
        if mode == "large":
            print("PASS large immutable index serves touched metadata within a smaller node budget", flush=True)
        print("PASS actual confined FUSE transport " + mode, flush=True)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        child_socket.close()
        supervisor.close()
        backing_child.close()
        backing_server.close()
        if release is not None:
            release.set()
        if backing is not None:
            os.close(backing)
        if child is not None:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if child.stderr is not None:
                diagnostic = child.stderr.read().decode(errors="replace")
                if diagnostic:
                    print(diagnostic, file=sys.stderr, flush=True)
                child.stderr.close()
        if executor is not None:
            executor.shutdown(wait=True)
        if mounted:
            unmount(target)
        target.rmdir()


if __name__ == "__main__":
    executable, directory = map(pathlib.Path, sys.argv[1:])
    for selected in ["serve", "metadata", "read", "late", "multi", "large", "readiness", "timeout", "cancel"]:
        scenario(executable, directory, selected)
