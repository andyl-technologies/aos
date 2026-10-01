"""Install independently selected shared codecs for real fixture controls.

The selected source-built executable prepares private issuer/ingress messages;
it neither dispatches a provider mutation nor accepts a qualification artifact.
Its final codec source must be independently correlated with deployed binaries.
"""

import base64
import hashlib
import json
from pathlib import Path
import re


def install_direct_control_executable(native, tools, executable, digest):
    """Transfer bounded chunks through the agent without an undeclared mount."""
    destination = "/var/lib/hybrid-shared-controls/aos-fleet-controls"
    original = json.loads(direct_guest_python(native, tools["python"], """
        import os
        from pathlib import Path

        target = Path(selected['destination'])
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            metadata = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        print(json.dumps({'device': metadata.st_dev, 'inode': metadata.st_ino}))
    """, {"destination": destination}))
    # Agent requests have a 16MiB frame bound. Chunking keeps preparation
    # independent of executable/debug size without exposing helper bytes in logs.
    for offset in range(0, len(executable), 128 * 1024):
        chunk = executable[offset:offset + 128 * 1024]
        direct_guest_python(native, tools["python"], """
            import os, stat

            descriptor = os.open(selected['destination'], os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                metadata = os.fstat(descriptor)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                        or metadata.st_mode & 0o7777 != 0o600 or metadata.st_nlink != 1
                        or metadata.st_dev != selected['device'] or metadata.st_ino != selected['inode']
                        or metadata.st_size != selected['offset']):
                    raise ValueError('partial shared executable differs from its retained original')
                body = base64.b64decode(selected['chunk'], validate=True)
                if not 1 <= len(body) <= 128 * 1024:
                    raise ValueError('shared executable transfer chunk exceeds its bound')
                os.lseek(descriptor, 0, os.SEEK_END)
                while body:
                    written = os.write(descriptor, body)
                    if written <= 0:
                        raise ValueError('shared executable transfer made no progress')
                    body = body[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            print('{}')
        """, {"destination": destination, **original, "offset": offset,
            "chunk": base64.b64encode(chunk).decode()})
    installed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat

        descriptor = os.open(selected['destination'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_mode & 0o7777 != 0o600 or before.st_nlink != 1
                    or before.st_dev != selected['device'] or before.st_ino != selected['inode']
                    or before.st_size != selected['byteSize']):
                raise ValueError('completed shared executable custody differs')
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
            after = os.fstat(source.fileno())
            if digest != selected['sha256'] or any(getattr(before, field) != getattr(after, field)
                    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError('completed shared executable bytes changed')
            os.fchmod(source.fileno(), 0o500)
        print(json.dumps({'file': selected['destination'], 'sha256': digest,
            'byteSize': before.st_size, 'device': before.st_dev, 'inode': before.st_ino}))
    """, {"destination": destination, **original, "byteSize": len(executable), "sha256": digest}))
    return installed


def install_direct_shared_controls(native, tools, artifacts):
    """Bind a reviewed helper and explicit AOS library closure to installed bytes."""
    reviewed = await_direct_review("shared-runtime-controls", {
        "installedArtifacts": retain_direct_flow("shared-control-installed-inputs.json", artifacts),
    }, {"controlExecutable", "controlProvenance"})
    selected = reviewed["selection"]
    provenance = _closed_review_json(direct_selected_bytes(selected["controlProvenance"], 65536))
    fields = {"version", "codecRevision", "nativeExecutableSha256", "workerSourceDigest",
        "executableSha256", "helperSourceSha256", "helperLockSha256", "runtimeRoots"}
    if (not isinstance(provenance, dict) or set(provenance) != fields
            or type(provenance["version"]) is not int or provenance["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["codecRevision"])
            or provenance["nativeExecutableSha256"] != artifacts["files"]["nativeHub"]["sha256"]
            or provenance["workerSourceDigest"] != artifacts["buildDerivedSourceDigest"]
            or provenance["executableSha256"] != selected["controlExecutable"]["sha256"]
            or provenance["runtimeRoots"] != tools["sharedControlRuntimeRoots"]):
        raise ValueError("shared fixture codec provenance differs from the actual runtime")
    for name in ("helperSourceSha256", "helperLockSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", provenance[name]):
            raise ValueError("shared fixture helper lacks selected source/lock commitments")
    executable = direct_selected_bytes(selected["controlExecutable"], 512 * 1024 * 1024)
    if not executable.startswith(b"\x7fELF"):
        raise ValueError("shared fixture helper is not the reviewed ELF executable")
    destination = "/var/lib/hybrid-shared-controls/aos-fleet-controls"
    installed = install_direct_control_executable(native, tools, executable, provenance["executableSha256"])
    if installed["sha256"] != provenance["executableSha256"]:
        raise ValueError("shared fixture executable changed during installation")
    libraries = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat, subprocess
        from pathlib import Path

        target = Path(selected['executable'])
        target.chmod(0o500)
        for name in selected['roots']:
            root = Path(name)
            metadata = root.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022):
                raise ValueError('selected AOS runtime library root custody differs')
        # This is the explicit AOS ELF interpreter, not the host's loader.
        result = subprocess.run([selected['interpreter'], '--list', str(target)],
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=15)
        if result.returncode or len(result.stdout) > 65536 or result.stderr:
            raise ValueError('selected shared codec AOS library closure is unavailable')
        library_paths = []
        for line in result.stdout.decode().splitlines():
            for item in line.split():
                if item.startswith('/nix/store/'):
                    library_paths.append(item)
        records = []
        for name in sorted(set(library_paths)):
            if not any(name.startswith(root + '/') for root in selected['roots']):
                raise ValueError('shared codec resolved an undeclared runtime library')
            with open(name, 'rb') as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            records.append({'file': name, 'sha256': digest, 'byteSize': os.stat(name).st_size})
        if not records:
            raise ValueError('shared codec has no observed AOS library resolution')
        with target.open('rb') as source:
            executable_digest = hashlib.file_digest(source, 'sha256').hexdigest()
        print(json.dumps({'version': 1, 'libraries': records,
            'executableSha256': executable_digest,
            'scope': 'actual selected ELF/library installation only; no provider or authority acceptance'}))
    """, {"executable": destination, "roots": tools["sharedControlRuntimeRoots"],
        "interpreter": tools["sharedControlInterpreter"]}, timeout=30))
    if libraries["executableSha256"] != provenance["executableSha256"]:
        raise ValueError("installed shared codec changed during library observation")
    return {"executable": destination, "executableSha256": provenance["executableSha256"],
        "codecRevision": provenance["codecRevision"],
        "installationSha256": retain_direct_flow("shared-control-installation.json", libraries),
        "provenanceSha256": retain_direct_flow("shared-control-provenance.json", provenance)}


def run_direct_shared_control(native, tools, helper, selection, label):
    """Execute the held reviewed inode with one private selected operation."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label):
        raise ValueError("shared control observation label is invalid")
    request = "/var/lib/hybrid-shared-controls/" + label + ".selection.json"
    install_direct_guest_file(native, tools["python"], request,
        json.dumps(selection, sort_keys=True, separators=(",", ":")).encode())
    execution = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat, subprocess

        descriptor = os.open(selected['executable'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_mode & 0o077 or before.st_nlink != 1
                    or not before.st_mode & 0o100 or before.st_size > 512 * 1024 * 1024):
                raise ValueError('selected shared executable custody differs')
            with os.fdopen(os.dup(descriptor), 'rb') as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            after = os.fstat(descriptor)
            if digest != selected['sha256'] or any(getattr(before, field) != getattr(after, field)
                    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError('shared executable changed before invocation')
            result = subprocess.run(['/proc/self/fd/' + str(descriptor), selected['request']],
                pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
                capture_output=True, check=False, timeout=20)
        finally:
            os.close(descriptor)
        if len(result.stdout) > 65536 or len(result.stderr) > 4096:
            raise ValueError('shared codec reply exceeds fixture observation bound')
        print(json.dumps({'version': 1, 'exitCode': result.returncode,
            'stdout': result.stdout.decode(), 'stderrSha256': hashlib.sha256(result.stderr).hexdigest(),
            'stderrBytes': len(result.stderr), 'executableSha256': digest}))
    """, {"executable": helper["executable"], "sha256": helper["executableSha256"],
        "request": request}, timeout=30))
    retain_direct_flow("shared-control-" + label + ".json", execution)
    if execution["exitCode"] != 0 or execution["stderrBytes"]:
        raise RuntimeError("actual shared codec refused; selected evidence retained")
    report = _closed_review_json(execution["stdout"])
    if report["codecRevision"] != helper["codecRevision"] or report["version"] != 1:
        raise ValueError("shared codec report differs from independently selected source")
    return report
