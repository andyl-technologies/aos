"""Qualifies original Rust FUSE device exchanges in a disposable native VM."""

import array
import ctypes
import errno
import os
import pathlib
import socket
import stat
import subprocess
import sys


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


def scenario(executable, directory, mode):
    """Transfers one mount alias, then observes the worker's sole original fd."""
    target = directory / mode
    target.mkdir()
    supervisor, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    supervisor.settimeout(5)
    child = None
    mounted = False
    descriptors = []
    try:
        child = subprocess.Popen([
            "setpriv", "--reuid=840", "--regid=840", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", str(executable), mode,
        ], stdin=subprocess.DEVNULL, stdout=child_socket, stderr=subprocess.PIPE,
            close_fds=True)
        child_socket.close()
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

        if mode in {"serve", "metadata"}:
            metadata = target.stat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o7777 == 0o555
                    and metadata.st_ino == 16
                    and metadata.st_nlink == (3 if mode == "metadata" else 2)
                    and (metadata.st_uid, metadata.st_gid) == (0, 0)
                    and metadata.st_atime_ns == 1_000_000_000
                    and metadata.st_mtime_ns == 1_000_000_000
                    and metadata.st_ctime_ns == 1_000_000_000,
                    "actual GETATTR reply differs from fixture root")
            if mode == "serve":
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
        print("PASS actual confined FUSE transport " + mode, flush=True)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        child_socket.close()
        supervisor.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if child.stderr is not None:
                diagnostic = child.stderr.read().decode(errors="replace")
                if diagnostic:
                    print(diagnostic, file=sys.stderr, flush=True)
                child.stderr.close()
        if mounted:
            unmount(target)
        target.rmdir()


if __name__ == "__main__":
    executable, directory = map(pathlib.Path, sys.argv[1:])
    for selected in ["serve", "metadata", "timeout", "cancel"]:
        scenario(executable, directory, selected)
