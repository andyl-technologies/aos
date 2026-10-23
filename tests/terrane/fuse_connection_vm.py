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
                     2 | 4, options.encode()) != 0:
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

        if mode == "serve":
            metadata = target.stat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & 0o7777 == 0o555
                    and metadata.st_ino == 1, "actual GETATTR reply differs from fixture root")
            require(os.listdir(target) == [], "actual READDIR reply was not empty")
            try:
                (target / "absent").stat()
            except OSError as error:
                require(error.errno == errno.ENOENT, "actual LOOKUP lost its errno")
            else:
                raise RuntimeError("missing fixture path unexpectedly exists")
            unmount(target)
            mounted = False
            require(supervisor.recv(64) == b"UNMOUNTED", "worker lost actual unmount errno")
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
    for selected in ["serve", "timeout", "cancel"]:
        scenario(executable, directory, selected)
