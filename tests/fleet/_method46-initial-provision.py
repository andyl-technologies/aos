"""Runs installed initial producers with external inputs and a host-only approver."""

import base64
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tempfile
import time
from uuid import UUID


PURPOSES = ("controller", "storage")
DIRECTORIES = {
    "controller": "/lib/aos/sandboxd/broker-session/storage",
    "storage": "/lib/aos/sandbox-storage/broker-session",
}
# Published RFC 8032 test vectors, not production operator secrets. These
# identities are confined to the host driver; normal-owner keys are fresh.
OPERATOR_TEST_SEEDS = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
)


def run(arguments):
    return subprocess.run(list(map(str, arguments)), check=True, capture_output=True, text=True)


def private_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def wait_until(predicate, deadline, message):
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(0.02)


@contextmanager
def external_tpm(scratch):
    """Opens the stopped persistent TPM state without clearing or replacing NV."""
    assert vm.qemu_proc.poll() is not None
    assert vm.swtpm_proc is None or vm.swtpm_proc.poll() is not None
    with tempfile.TemporaryDirectory(prefix="tpm-", dir=scratch) as directory:
        directory = Path(directory)
        data, control = directory / "socket", directory / "socket.ctrl"
        with (directory / "backend.log").open("wb") as log:
            backend = subprocess.Popen([
                vm.swtpm_bin, "socket", "--tpm2", f"--tpmstate=dir={vm.tpm_state_dir}",
                f"--server=type=unixio,path={data}", f"--ctrl=type=unixio,path={control}",
                "--flags=not-need-init,startup-clear",
            ], stdout=log, stderr=log)
            try:
                def ready():
                    assert backend.poll() is None, "external TPM backend exited"
                    return data.exists() and control.exists()

                wait_until(ready, time.monotonic() + 5, "external TPM socket timeout")
                yield data
                run([Path(tools["tpm"]) / "tpm2_shutdown", "-T", f"swtpm:path={data}", "-c"])
            finally:
                backend.terminate()
                try:
                    backend.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    backend.kill()
                    backend.wait(timeout=5)


def debugfs(image, offset, command):
    # debugfs can exit zero for a refused command. Every mutation below needs
    # independent bytes and metadata readbacks, not merely a process status.
    return run([tools["debugfs"], "-w", "-R", command, f"{image}?offset={offset}"]).stdout


def install_histories(image, offset, native, scratch):
    for purpose in PURPOSES:
        directory = DIRECTORIES[purpose]
        owner = 811 if purpose == "controller" else 0
        stat = debugfs(image, offset, f"stat {directory}")
        assert "Type: directory" in stat, (directory, stat)
        assert re.search(r"Mode:\s+0700", stat), stat
        assert re.search(fr"User:\s+{owner}\s+Group:\s+{owner}", stat), stat
        label = f"system_u:object_r:aos_method46_{purpose}_floor_t"
        assert label in debugfs(image, offset, f"ea_get {directory} security.selinux")

        for name in ("session.journal", "session.journal.lock"):
            destination = f"{directory}/{name}"
            assert "Inode:" not in debugfs(image, offset, f"stat {destination}"), destination
            debugfs(image, offset, f"write {native / name} {destination}")
            debugfs(image, offset, f"set_inode_field {destination} mode 0100600")
            debugfs(image, offset, f"set_inode_field {destination} uid {owner}")
            debugfs(image, offset, f"set_inode_field {destination} gid {owner}")
            kind = "main" if name == "session.journal" else "lock"
            label = f"system_u:object_r:aos_method46_{purpose}_{kind}_t"
            debugfs(image, offset, f"ea_set {destination} security.selinux {label}")
            readback = scratch / f"{purpose}-{name}"
            debugfs(image, offset, f"dump {destination} {readback}")
            assert readback.read_bytes() == (native / name).read_bytes()
            stat = debugfs(image, offset, f"stat {destination}")
            assert re.search(r"Mode:\s+0600", stat), stat
            assert re.search(fr"User:\s+{owner}\s+Group:\s+{owner}", stat), stat
            assert re.search(r"Links:\s+1", stat), stat
            assert label in debugfs(image, offset, f"ea_get {destination} security.selinux")
    with image.open("rb") as stream:
        os.fsync(stream.fileno())


def guest_input_files(files):
    """Delivers bounded external inputs without logging private command contents."""
    payload = {str(path): base64.b64encode(data).decode() for path, data in files.items()}
    script = (
        "import base64,json,os,pathlib; os.umask(0o077)\n"
        f"files=json.loads({json.dumps(json.dumps(payload))})\n"
        "for name,value in files.items():\n"
        " path=pathlib.Path(name); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)\n"
        " with path.open('xb') as stream:\n"
        "  stream.write(base64.b64decode(value)); stream.flush(); os.fsync(stream.fileno())\n"
    )
    # The ordinary machine wrapper logs command text. Use the same agent wire
    # channel directly so private index auth and normal seeds stay out of logs.
    command = f"{tools['python']} -c {shlex.quote(script)}"
    status, _, stderr = vm.agent.request(command.encode(), timeout=30)
    assert status == 0, stderr.decode(errors="replace")


def deliver_credentials(directory):
    guest_input_files({
        Path("/run/credentials/@system") / path.name: path.read_bytes()
        for path in directory.iterdir()
    })


def manual_properties(purpose):
    unit = f"aos-sandbox-{purpose}-floor-initialize.service"
    properties = "LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result"
    return dict(line.split("=", 1) for line in vm.succeed(
        f"systemctl show {unit} --property={properties}"
    ).splitlines())


def require_unstarted():
    for purpose in PURPOSES:
        properties = manual_properties(purpose)
        assert properties["LoadState"] == "loaded", properties
        assert properties["ActiveState"] == "inactive", properties
        assert properties["SubState"] == "dead", properties
        assert properties["MainPID"] == properties["ExecMainPID"] == "0", properties


def approve_installed(purpose, scratch, delivered, expectations, seed, public, defer_completion=False):
    """Keeps the actual guest peer alive through all producer posts."""
    print(f"Starting installed {purpose} producer and administrative peer", flush=True)
    root = Path("/run/method46-qualification") / purpose
    peer = f"""
import os,pathlib,socket,time
assert pathlib.Path('/proc/self/attr/current').read_text().rstrip('\\0\\n') == 'system_u:system_r:unconfined_t'
root=pathlib.Path({str(root)!r})
root.mkdir(mode=0o700,parents=True)
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
    channel.settimeout(90)
    channel.connect('/run/aos/sandbox/method46-{purpose}-initial.sock')
    request=channel.recv(323)
    assert len(request)==322
    with (root/'request').open('xb') as output:
        output.write(request); output.flush(); os.fsync(output.fileno())
    deadline=time.monotonic()+90
    while not (root/'signature').exists():
        assert time.monotonic()<deadline
        time.sleep(0.01)
    signature=(root/'signature').read_bytes()
    assert len(signature)==64 and channel.send(signature)==64
    # EOF is not proof that the producer has completed its independent posts.
    while not (root/'release').exists():
        assert time.monotonic()<deadline
        time.sleep(0.01)
"""
    unit = f"aos-sandbox-{purpose}-floor-initialize"
    vm.succeed(f"systemctl start {unit}.socket")
    vm.succeed(
        f"umask 077; {tools['operator']} -c {shlex.quote(peer)} "
        f">/run/method46-{purpose}-peer.log 2>&1 </dev/null &"
    )
    deadline = time.monotonic() + 90

    def request_ready():
        status, _, _ = vm.execute(f"test -f {root}/request")
        if status == 0:
            return True
        properties = manual_properties(purpose)
        assert properties["ActiveState"] != "failed", properties
        return False

    try:
        wait_until(request_ready, deadline, f"{purpose} request was not published")
    except Exception:
        print(vm.succeed(f"tail -c 8192 /run/method46-{purpose}-peer.log"), flush=True)
        raise
    request = scratch / f"{purpose}-request"
    private_file(request, base64.b64decode(vm.succeed(f"base64 -w0 {root}/request")))
    signature = scratch / f"{purpose}-signature"
    prefix = f"qualification-method46-{purpose}"
    run([
        tools["approval"], purpose, delivered / f"{prefix}-provision",
        expectations / f"{purpose}-checkpoint", request, seed, public, signature,
    ])
    guest_input_files({root / "signature": signature.read_bytes()})

    transcript = request.read_bytes(), signature.read_bytes()
    if not defer_completion:
        wait_initial_complete(purpose, deadline)
        vm.succeed(f"touch {root}/release")
    return transcript


def wait_initial_complete(purpose, deadline):
    def complete():
        properties = manual_properties(purpose)
        assert properties["ActiveState"] != "failed", properties
        if properties["ActiveState"] != "inactive" or properties["ExecMainPID"] == "0":
            return False
        assert properties["Result"] == "success", properties
        assert properties["ExecMainCode"] == "1" and properties["ExecMainStatus"] == "0", properties
        return True

    wait_until(complete, deadline, f"{purpose} producer did not complete")
    print(f"Installed {purpose} producer completed all posts", flush=True)


def observe_floors(socket, prepared, expectations, scratch, states=None):
    """Authenticates retained NV areas and, when written, their exact values."""
    def tpm(command, *arguments):
        return run([Path(tools["tpm"]) / f"tpm2_{command}", "-T", f"swtpm:path={socket}", *arguments])

    states = {purpose: True for purpose in PURPOSES} if states is None else states
    with tempfile.TemporaryDirectory(prefix="observed-floor-", dir=scratch) as temporary:
        observed = Path(temporary)
        for purpose, written in states.items():
            role = PURPOSES.index(purpose)
            record = (prepared / f"endpoint-{role}").read_bytes()
            salt_name, auth, session = (observed / f"{purpose}-{name}" for name in ("salt", "auth", "session"))
            private_file(salt_name, record[32:66])
            private_file(auth, record[:32])
            index, salt = hex(0x0180a046 + role), hex(0x8100a046 + role)
            tpm("startauthsession", "--hmac-session", "--tpmkey-context", salt,
                "--name", salt_name, "--session", session)
            try:
                tpm("sessionconfig", "--enable-encrypt", session)
                public = tpm("nvreadpublic", "-S", session, index).stdout
                attributes = 0x20040044 if written else 0x00040044
                expected_public = struct.pack(">IHIHH", 0x0180a046 + role, 0x000b, attributes, 0, 32)
                name = "000b" + hashlib.sha256(expected_public).hexdigest()
                assert f"  name: {name}\n" in public, public
                assert f"    value: {attributes:#x}\n" in public and "  size: 32\n" in public, public
                if written:
                    value = observed / f"{purpose}-nv-readback"
                    tpm("nvread", index, "-C", index, "-P", f"session:{session}+file:{auth}",
                        "-s", "32", "-o", value)
                    assert value.read_bytes() == (expectations / f"{purpose}-nv").read_bytes()
            finally:
                tpm("flushcontext", session)


def install_command_gate(purpose, relays):
    # _launch reuses this same live backend and passes its real data descriptor
    # through the relay. No TPM state is cleared, replaced or restored.
    vm._ensure_swtpm()
    edge = "after-response" if initial_cut == "partial-publication" else initial_cut
    return relays.enter_context(Method46TpmCommandGate(
        vm.tpm_socket, 0x0180a046 + PURPOSES.index(purpose), edge,
    ))


def limit_checkpoint_write(purpose):
    """Limits the real producer after its durable intent and actual NV Extend."""
    properties = manual_properties(purpose)
    assert properties["ActiveState"] == "active", properties
    pid = int(properties["MainPID"])
    assert pid > 0 and properties["ExecMainPID"] == str(pid), properties
    script = f"""
import os,pathlib,resource,select,signal,time
pid={pid}
descriptor=os.pidfd_open(pid)
try:
    signal.pidfd_send_signal(descriptor,signal.SIGSTOP)
    try:
        deadline=time.monotonic()+5
        while True:
            assert not select.select([descriptor],[],[],0)[0], 'producer exited'
            status=pathlib.Path(f'/proc/{{pid}}/status').read_text().splitlines()
            state=next(line for line in status if line.startswith('State:')).split()[1]
            if state=='T':
                break
            assert time.monotonic()<deadline, 'producer did not stop'
            time.sleep(0.01)
        soft,hard=resource.prlimit(pid,resource.RLIMIT_FSIZE)
        assert soft==resource.RLIM_INFINITY or soft>=429
        assert hard==resource.RLIM_INFINITY or hard>=429
        resource.prlimit(pid,resource.RLIMIT_FSIZE,(128,128))
        assert resource.prlimit(pid,resource.RLIMIT_FSIZE)==(128,128)
    finally:
        signal.pidfd_send_signal(descriptor,signal.SIGCONT)
finally:
    os.close(descriptor)
"""
    vm.succeed(f"{tools['operator']} -c {shlex.quote(script)}")
    return pid


def require_partial_prefix(purpose, expectations):
    path = "/var" + DIRECTORIES[purpose] + "/session-floor.journal.initial.pending"
    script = f"import base64,pathlib; print(base64.b64encode(pathlib.Path({path!r}).read_bytes()).decode())"
    observed = base64.b64decode(vm.succeed(f"{tools['operator']} -c {shlex.quote(script)}"))
    expected = (expectations / f"{purpose}-sidecar").read_bytes()
    assert len(expected) == 429 and observed == expected[:128], (purpose, len(observed))


def finish_short_publication(purpose, gate, expectations):
    pid = limit_checkpoint_write(purpose)
    gate.release()

    def failed():
        properties = manual_properties(purpose)
        if properties["ActiveState"] != "failed":
            return False
        assert properties["MainPID"] == "0" and properties["ExecMainPID"] == str(pid), properties
        assert properties["Result"] == "exit-code", properties
        assert properties["ExecMainCode"] == "1" and properties["ExecMainStatus"] == "1", properties
        return True

    wait_until(failed, time.monotonic() + 90, f"{purpose} short publication did not fail")
    vm.succeed(f"touch /run/method46-qualification/{purpose}/release")
    require_partial_prefix(purpose, expectations)


def require_interrupted_files(purpose, transcript, native):
    directory = "/var" + DIRECTORIES[purpose]
    script = (
        "import base64,json,pathlib; "
        f"root=pathlib.Path({directory!r}); "
        "print(json.dumps({name:base64.b64encode((root/name).read_bytes()).decode() "
        "for name in ('session.journal','session-floor.journal','session-floor.initial-intent')}))"
    )
    observed = json.loads(vm.succeed(f"{tools['operator']} -c {shlex.quote(script)}"))
    expected = {
        "session.journal": (native / "session.journal").read_bytes(),
        "session-floor.journal": b"",
        "session-floor.initial-intent": b"AOSBII01\0\x01\0\0" + b"".join(transcript),
    }
    for name, value in expected.items():
        assert base64.b64decode(observed[name]) == value, (purpose, name)


def recover_after_initial_cut(purpose, gate, transcript, prepared, expectations,
                              delivered, native, scratch, relays):
    gate.wait_reached(60)
    assert gate.forwarded_extends == (0 if initial_cut == "before-command" else 1)
    if initial_cut == "partial-publication":
        finish_short_publication(purpose, gate, expectations)
        require_interrupted_files(purpose, transcript, native)
    before_cut = UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip())
    role = PURPOSES.index(purpose)
    next_gate = None
    original_launch = vm._launch

    def launch_after_observation():
        nonlocal next_gate
        # Both owned processes have been stopped and reaped by the harness.
        # Observe the actual retained TPM before any replacement QEMU boots.
        gate.close()
        with external_tpm(scratch) as endpoint:
            observe_floors(endpoint, prepared, expectations, scratch, {
                purpose: initial_cut != "before-command",
            })
        if role + 1 < len(PURPOSES):
            next_gate = install_command_gate(PURPOSES[role + 1], relays)
        original_launch()

    try:
        if initial_cut == "partial-publication":
            # This case proves recovery after resource failure and a clean
            # shutdown, separately from the two interrupted-Extend power cuts.
            vm._stop_runtime_for_relaunch(120)
            assert vm.qemu_proc.returncode == 0, "guest shutdown did not complete cleanly"
            launch_after_observation()
            vm.agent.wait_ready(time.monotonic() + 300)
        else:
            vm._launch = launch_after_observation
            vm.power_cycle()
    finally:
        vm._launch = original_launch
        gate.close()

    vm.wait_for_unit("multi-user.target", timeout=300)
    vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
    assert UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()) != before_cut
    require_unstarted()
    # Let ext4 replay its own journal before observing the durable intent.
    # Reading raw inode tables before replay would not establish fsync loss.
    require_interrupted_files(purpose, transcript, native)
    if initial_cut == "partial-publication":
        require_partial_prefix(purpose, expectations)
    deliver_credentials(delivered)
    vm.succeed(f"test ! -e /run/method46-qualification/{purpose}")
    vm.execute(f"systemctl start aos-sandbox-{purpose}-floor-initialize.service")
    wait_initial_complete(purpose, time.monotonic() + 90)
    print(f"Cold {purpose} recovery completed without a new approval peer", flush=True)
    return next_gate


with tempfile.TemporaryDirectory(prefix="method46-installed-") as temporary:
    scratch = Path(temporary)
    units = [f"aos-sandbox-{purpose}-floor-initialize.service" for purpose in PURPOSES]
    with startup_diagnostics(vm, *units), ExitStack() as relays:
        vm.wait_for_unit("multi-user.target", timeout=300)
        vm.wait_for_unit("aos-activate.service", timeout=60)
        vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1; test -c /dev/tpmrm0")
        require_unstarted()
        context_probe = "from pathlib import Path; print(Path('/proc/self/attr/current').read_text().rstrip('\\0\\n'))"
        assert vm.succeed(f"{tools['operator']} -c {shlex.quote(context_probe)}").strip() == "system_u:system_r:unconfined_t"
        print("First enforcing boot and administrative context checks passed", flush=True)
        first_boot = UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip())
        assert first_boot.int != 0
        filesystem, device = vm.succeed("findmnt -n -o FSTYPE,SOURCE /var").split()
        assert filesystem == "ext4" and re.fullmatch(r"/dev/vda[0-9]+", device), (filesystem, device)
        partition = Path(device).name
        start = int(vm.succeed(f"cat /sys/class/block/{partition}/start").strip()) * 512
        size = int(vm.succeed(f"cat /sys/class/block/{partition}/size").strip()) * 512
        assert start > 0 and size > 0 and start + size <= Path(vm.disk_copy).stat().st_size
        vm._stop_runtime_for_relaunch(120)

        prepared = scratch / "tpm-preparation"
        with external_tpm(scratch) as endpoint:
            assert "both indices remain unwritten" in run([tools["preparation"], endpoint, prepared]).stdout
        native = scratch / "native-history"
        run([tools["history"], native])
        node, epoch = scratch / "node", scratch / "epoch"
        private_file(node, bytes([0x11]) * 16)
        private_file(epoch, bytes([0x33]) * 16)
        pins, seeds = [], []
        for purpose, seed in zip(PURPOSES, OPERATOR_TEST_SEEDS):
            public, private = scratch / f"{purpose}-public", scratch / f"{purpose}-seed"
            private_file(public, bytes(approval_pins[purpose]))
            private_file(private, bytes.fromhex(seed))
            pins.append(public)
            seeds.append(private)
        bundle = scratch / "credentials"
        run([tools["credentials"], node, epoch, prepared, *pins, native / "expected-cut.json", bundle])
        delivered, expectations = bundle / "system-credentials", bundle / "operator-expectations"
        install_histories(Path(vm.disk_copy), start, native, scratch)
        print("External TPM and native history prepared on stopped state", flush=True)

        gate = install_command_gate(PURPOSES[0], relays) if initial_cut else None
        vm._launch()
        vm.agent.wait_ready(time.monotonic() + 300)
        vm.wait_for_unit("multi-user.target", timeout=300)
        assert UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()) != first_boot
        require_unstarted()
        vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
        print("Prepared-state enforcing boot checks passed", flush=True)
        deliver_credentials(delivered)
        approvals = {}
        for role, purpose in enumerate(PURPOSES):
            if gate is not None:
                gate.arm()
            approvals[purpose] = approve_installed(
                purpose, scratch, delivered, expectations, seeds[role], pins[role],
                defer_completion=gate is not None,
            )
            if gate is not None:
                gate = recover_after_initial_cut(
                    purpose, gate, approvals[purpose], prepared, expectations,
                    delivered, native, scratch, relays,
                )

        # The completed producers have returned from their native helper and
        # publication posts. Kill both QEMU and swtpm, retaining their same state.
        before_cut = UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip())
        vm.power_cycle()
        vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
        print("Power cycle completed after both initial producers", flush=True)
        assert UUID(vm.succeed("cat /proc/sys/kernel/random/boot_id").strip()) != before_cut
        vm.wait_for_unit("multi-user.target", timeout=300)
        require_unstarted()
        deliver_credentials(delivered)
        for purpose in PURPOSES:
            # Type=exec can report a successful start before the producer
            # refuses the already initialized state. Observe its actual exit.
            vm.execute(f"systemctl start aos-sandbox-{purpose}-floor-initialize.service")

            def repeat_refused():
                properties = manual_properties(purpose)
                if properties["ActiveState"] != "failed":
                    return False
                assert properties["ExecMainPID"] != "0", properties
                assert properties["Result"] == "exit-code", properties
                assert properties["ExecMainCode"] == "1", properties
                assert properties["ExecMainStatus"] != "0", properties
                return True

            wait_until(repeat_refused, time.monotonic() + 90, f"{purpose} repeat was not refused")
        vm._stop_runtime_for_relaunch(120)

        for purpose in PURPOSES:
            directory = DIRECTORIES[purpose]
            expected_files = {
                "session.journal": (native / "session.journal").read_bytes(),
                "session-floor.journal": (expectations / f"{purpose}-sidecar").read_bytes(),
                "session-floor.journal.initial.pending": b"",
                "session-floor.initial-intent": b"AOSBII01\0\x01\0\0" + b"".join(approvals[purpose]),
            }
            for name, expected in expected_files.items():
                readback = scratch / f"completed-{purpose}-{name}"
                debugfs(vm.disk_copy, start, f"dump {directory}/{name} {readback}")
                assert readback.read_bytes() == expected, (purpose, name)
        with external_tpm(scratch) as endpoint:
            observe_floors(endpoint, prepared, expectations, scratch)
