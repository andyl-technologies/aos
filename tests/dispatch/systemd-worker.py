"""Exercises managed worker accounting using real descendants and allocations."""

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading


def cgroup():
    for line in pathlib.Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line.removeprefix("0::")
    raise RuntimeError("unified cgroup membership is unavailable")


def native():
    print(json.dumps({"pid": os.getpid(), "cgroup": cgroup()}), flush=True)
    threads = []
    held = []
    stop = threading.Event()

    for line in sys.stdin:
        command = line.strip()
        if command == "tasks":
            limited = False
            for _ in range(256):
                try:
                    thread = threading.Thread(target=stop.wait, daemon=True)
                    thread.start()
                    threads.append(thread)
                except RuntimeError:
                    limited = True
                    break

            directory = pathlib.Path("/sys/fs/cgroup") / cgroup().lstrip("/")
            print(json.dumps({
                "limited": limited,
                "threads_created": len(threads),
                "pids_current": int((directory / "pids.current").read_text()),
            }), flush=True)
        elif command == "memory":
            # Keep every touched page live. The parent stays small, so the
            # constrained native descendant is the expected OOM victim.
            allocations = []
            while True:
                block = bytearray(4 * 1024 * 1024)
                for index in range(0, len(block), 4096):
                    block[index] = 1
                allocations.append(block)
        elif command == "hold":
            block = bytearray(60 * 1024 * 1024)
            for index in range(0, len(block), 4096):
                block[index] = 1
            held.append(block)
            print(json.dumps({"held_bytes": len(block)}), flush=True)
        elif command == "hello":
            print(json.dumps({"pid": os.getpid(), "cgroup": cgroup()}), flush=True)
        else:
            raise RuntimeError(f"unknown fixture command: {command}")


def runner():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connect", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--backend-arg", action="append", default=[])
    parser.add_argument("--max-frame-bytes", required=True)
    arguments = parser.parse_args()

    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.connect(arguments.connect)
    child = subprocess.Popen(
        [arguments.backend, *arguments.backend_arg],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    try:
        initial = json.loads(child.stdout.readline())
        initial["runner_pid"] = os.getpid()
        initial["runner_cgroup"] = cgroup()
        channel.sendall((json.dumps(initial) + "\n").encode())

        with channel.makefile("r") as incoming:
            for command in incoming:
                child.stdin.write(command)
                child.stdin.flush()
                response = child.stdout.readline()
                if not response:
                    channel.sendall((json.dumps({"native_exit": child.wait()}) + "\n").encode())
                    # Keep this small runner and its leaf accounting alive until
                    # the controller reads the postmortem and stops the unit.
                    for _ in incoming:
                        pass
                    return
                channel.sendall(response.encode())
    finally:
        child.kill()
        child.wait()
        channel.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--native"]:
        native()
    else:
        runner()
