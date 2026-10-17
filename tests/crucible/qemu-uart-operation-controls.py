# SPDX-License-Identifier: Apache-2.0
"""Check real serial operation discrimination through QEMU's test socket.

An unbound native constructor must enter the original operation refusal, even
in loopback. An ordinary file bearing the native backend label must accept all
4096 bytes. These device controls do not grant authority or run a guest workload.
"""

import argparse
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def run_case(qemu, bios, output, case, cancellation):
    output.mkdir()
    with tempfile.TemporaryDirectory(prefix="uart-operation-") as directory:
        connection_path = str(Path(directory) / "qtest.sock")
        serial_path = output / "serial.bin"
        native = case != "ordinary-label"
        backend = ("crucible-console,id=crucible-console" if native else
                   f"file,id=crucible-console,path={serial_path}")
        argv = [str(qemu), "-L", str(bios), "-machine", "pc-i440fx-11.1",
                "-accel", "tcg,thread=single", "-smp", "1", "-nodefaults",
                "-display", "none", "-monitor", "none", "-S",
                "-chardev", backend, "-serial", "chardev:crucible-console",
                "-qtest", f"unix:{connection_path}",
                "-qtest-log", str(output / "qtest.log")]
        (output / "argv.txt").write_text("\n".join(argv) + "\n")
        listener = socket.socket(socket.AF_UNIX)
        process = None
        connection = None
        reader = None
        deadline = time.monotonic() + 10

        try:
            listener.bind(connection_path)
            listener.listen(1)
            listener.settimeout(10)
            with (output / "stdout").open("wb") as stdout, (output / "stderr").open("wb") as stderr:
                # Defer cancellation until Popen returns its owned child.
                # No signal mask is inherited by the new QEMU process.
                cancellation['spawning'] = True
                try:
                    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                               stdout=stdout, stderr=stderr)
                finally:
                    cancellation['spawning'] = False
                if cancellation['signal'] is not None:
                    raise InterruptedError('UART operation cancelled during child creation')
                connection, _ = listener.accept()
                reader = connection.makefile("rb")

                def request(command, expect_reply=True):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("UART operation control deadline expired")
                    connection.settimeout(remaining)
                    connection.sendall((command + "\n").encode())
                    for _ in range(16):
                        reply = reader.readline()
                        if reply.startswith(b"IRQ "):
                            continue
                        if expect_reply and reply != b"OK\n":
                            raise RuntimeError(f"unexpected qtest reply: {reply!r}")
                        if not expect_reply and reply:
                            raise RuntimeError("unbound native UART unexpectedly returned")
                        return
                    raise RuntimeError("too many asynchronous qtest replies")

                request("outb 0x3f9 0")
                if case == "native-loopback":
                    request("outb 0x3fc 0x10")
                if native:
                    request("outb 0x3f8 0x58", expect_reply=False)
                    status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if status != 1:
                        raise RuntimeError(f"native refusal exit differs: {status}")
                else:
                    for _ in range(4096):
                        request("outb 0x3f8 0x58")
                    if serial_path.read_bytes() != b"X" * 4096:
                        raise RuntimeError("ordinary labeled backend byte count/content differs")
                    if process.poll() is not None:
                        raise RuntimeError("ordinary QEMU exited before owned cleanup")

            if native:
                stderr = (output / "stderr").read_text()
                expected = "Crucible console refused: UART operation uses a foreign frontend"
                if stderr.count(expected) != 1 or "write outside the owned UART operation" in stderr:
                    raise RuntimeError("native operation-entry refusal reason differs")
        finally:
            # A catchable cancellation enters this cleanup. Defer subsequent
            # signals until the original owned child is killed and reaped.
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
            try:
                try:
                    if reader is not None:
                        reader.close()
                    if connection is not None:
                        connection.close()
                    listener.close()
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                        status = process.wait(timeout=5)
                        (output / "cleanup-status.txt").write_text(str(status) + "\n")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    (output / "result.txt").write_text("PASS " + case + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--bios", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    arguments.output.mkdir()

    cancellation = {'spawning': False, 'signal': None}

    def cancel(signum, frame):
        # The first cancellation owns cleanup; later signals must not interrupt it.
        if cancellation['signal'] is not None:
            return
        cancellation['signal'] = signum
        if cancellation['spawning']:
            return
        raise InterruptedError(f"UART operation control cancelled by signal {signum}")

    previous_handlers = {signum: signal.signal(signum, cancel)
                         for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        for case in ("native-thr", "native-loopback", "ordinary-label"):
            run_case(arguments.qemu.resolve(), arguments.bios.resolve(),
                     arguments.output.resolve() / case, case, cancellation)
            print("PASS UART operation " + case, flush=True)
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
