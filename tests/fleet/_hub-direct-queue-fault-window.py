"""Call ordinary production originals through explicitly selected queue faults.

This fixture owns preparation, observation and one-use boundaries. It neither
decodes admissions independently of Core nor treats transport success as current
SQL, actor, provider, or resource authority. Raw controls remain owner-private.
"""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


MAX_CONTROL = 256 * 1024
RUN = re.compile(r"[0-9a-f]{64}\Z")


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


faults = sibling("_hub-direct-queue-faults.py")
native_faults = sibling("_hub-direct-queue-fault-native.py")
setup = sibling("_hub-direct-queue-fault-setup.py")
staged = sibling("_hub-direct-staged-window.py")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def immutable_reference(reference, maximum):
    """Read the selected store file without following or accepting replacement."""
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not isinstance(reference["path"], str)
            or not reference["path"].startswith("/nix/store/")
            or not RUN.fullmatch(reference["sha256"])):
        raise ValueError("observation package reference is unavailable")
    path = Path(reference["path"])
    if path.resolve(strict=True) != path:
        raise ValueError("observation package reference traverses an alias")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError("observation package image exceeds its bound")
        with os.fdopen(os.dup(descriptor), "rb") as reader:
            raw = reader.read(maximum + 1)
        after = os.fstat(descriptor)
        if ((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw) != before.st_size
                or hashlib.sha256(raw).hexdigest() != reference["sha256"]):
            raise ValueError("observation package image changed")
        return raw
    finally:
        os.close(descriptor)


def require_admission_observer(tools, artifacts, identity, read=immutable_reference):
    """Require the actual feature-enabled package before any case has effects."""
    selected = tools.get("nativeBodyObservationTools")
    if (not isinstance(selected, dict)
            or set(selected) != {"package", "context", "provenance", "wrapper"}
            or not isinstance(selected["package"], str)
            or not selected["package"].startswith("/nix/store/")):
        raise ValueError("called queue faults require an independently selected admission observer")
    package = selected["package"]
    locators = {"context": "/libexec/aos-observation-tools/package-context.json",
                "provenance": "/helper-build-provenance.json",
                "wrapper": "/bin/aos-native-body-observer"}
    for name, suffix in locators.items():
        if selected[name].get("path") != package + suffix:
            raise ValueError("selected admission observer package locators differ")
    context_raw = read(selected["context"], MAX_CONTROL)
    provenance_raw = read(selected["provenance"], 4 * 1024 * 1024)
    wrapper_raw = read(selected["wrapper"], 16384)
    context = faults.runtime._direct_runtime_closed_json(context_raw.decode())
    provenance = faults.runtime._direct_runtime_closed_json(provenance_raw.decode())
    runtime = context["runtime"]
    inputs = provenance["runtimeInputs"]
    worker_source = artifacts["sourceStorePath"]
    worker_digest = hashlib.sha256(os.fsencode(worker_source)).hexdigest()
    if (context["version"] != 1 or provenance["version"] != 1
            or provenance["claim"] != "helper_build_only"
            or context["runtimeSource"] != tools["commonSourceStorePath"]
            or inputs["runtimeSource"] != context["runtimeSource"]
            or inputs["sourceTree"] != context["sourceTree"]
            or inputs["sourceCommit"] != runtime["runtimeCodecRevision"]
            or inputs["runtimeProvenance"] != context["runtimeProvenance"]
            or inputs["workerArtifact"] != artifacts["distributionStorePath"]
            or inputs["workerSourceDigest"] != worker_digest
            or runtime["workerSourceDigest"] != worker_digest
            or identity["identity"]["sourceDigest"] != worker_digest
            or runtime["nativeExecutableSha256"] != artifacts["files"]["nativeHub"]["sha256"]
            or any(context["runtimeProvenance"][name] != value for name, value in runtime.items())
            or not re.fullmatch(r"[0-9a-f]{40}", runtime["runtimeCodecRevision"])
            or not RUN.fullmatch(runtime["sourceArchiveSha256"])):
        raise ValueError("admission observer is not bound to the current measured application tuple")
    for reference, raw in [(provenance["context"], context_raw)]:
        if reference != {"file": selected["context"]["path"],
                         "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": str(len(raw))}:
            raise ValueError("admission observer context differs from its build record")
    wrapper_refs = [item for item in provenance["wrappers"]
                    if item["file"] == selected["wrapper"]["path"]]
    if wrapper_refs != [{"file": selected["wrapper"]["path"],
                         "sha256": hashlib.sha256(wrapper_raw).hexdigest(),
                         "byteSize": str(len(wrapper_raw))}]:
        raise ValueError("admission observer wrapper differs from its build record")
    executable = context["observerExecutable"]
    if (provenance["underlyingExecutable"] != executable
            or executable["file"] != provenance["codecOutput"] + "/bin/aos-storage-body-codec"):
        raise ValueError("admission observer underlying codec differs")
    body = read({"path": executable["file"], "sha256": executable["sha256"]}, 512 * 1024 * 1024)
    if str(len(body)) != executable["byteSize"]:
        raise ValueError("admission observer executable length differs")
    return {"package": package, "wrapper": selected["wrapper"], "executable": executable,
            "runtime": runtime, "context": selected["context"],
            "provenance": selected["provenance"], "qualification": None}


def retained_reference(root, name, raw):
    """Create a private host image once; paths never name credentials or seeds."""
    if Path(name).name != name or name in {".", ".."} or not isinstance(raw, bytes):
        raise ValueError("queue observation is not a direct private byte image")
    root = Path(root)
    metadata = root.lstat()
    if (root.resolve() != root or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("queue observation parent custody differs")
    descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as writer:
        writer.write(raw)
        writer.flush()
        os.fsync(writer.fileno())
    return {"file": str(root / name), "sha256": hashlib.sha256(raw).hexdigest(),
            "byteSize": str(len(raw))}


def selected_deadline(tools, maximum=180):
    """Reserve cleanup within the original fleet deadline; never pad the window."""
    remaining = tools["fleetCutoffMonotonic"] - time.monotonic()
    if remaining < maximum + 5:
        raise TimeoutError("queue fault window lacks its original remaining fleet budget")
    return int((time.time() + maximum) * 1000)


class ProductionQueueWindow:
    """Use the existing guest/process/capture owners on one selected cohort."""

    def __init__(self, client, native, worker, s3, database, tools, controls,
                 credentials, artifacts, identity, process, owners):
        self.client, self.native, self.worker, self.s3, self.database = client, native, worker, s3, database
        self.tools, self.controls, self.credentials = tools, controls, credentials
        self.artifacts, self.identity, self.process, self.owners = artifacts, identity, process, owners
        # This is deliberately first: no admission, process or provider operation
        # may happen in the absence of the independently selected Core package.
        self.observer = require_admission_observer(tools, artifacts, identity)
        self.root = Path("external-direct-flow/queue-faults").resolve()
        self.root.mkdir(mode=0o700, exist_ok=False)
        retained_reference(self.root, "observer-selection.json", encoded(self.observer))

    def guest(self, machine, code, selected, timeout=30):
        return self.owners["direct_guest_python"](machine, self.tools["python"], code, selected, timeout=timeout)

    def received(self, machine, path, maximum, reference=None, missing=False, *,
                 root=None, retain=None, terminal_pending=None):
        """Copy only owner-private regular files, with stable descriptor custody."""
        if (not isinstance(path, str) or not path.startswith("/var/lib/hybrid-")
                or any(part in {".", "..", ""} for part in path.split("/")[1:])):
            raise ValueError("queue received path escapes its exact guest fixture")
        if (type(maximum) is not int or not 0 < maximum <= (64 if root is None else 16) * 1024 * 1024
                or root is not None and (not isinstance(root, str)
                    or not root.startswith("/var/lib/hybrid-client/queue-faults/")
                    or any(part in {".", "..", ""} for part in root.split("/")[1:])
                    or not path.startswith(root + "/"))):
            raise ValueError("CLIENT reference escapes its independently selected private root")
        if (terminal_pending is not None and (maximum > 65536
                or Path(path).name != "exit.json"
                or terminal_pending != str(Path(path).with_name("exit.pending")))):
            raise ValueError("terminal publication is not the exact selected pending/final pair")
        raw = self.guest(machine, """
            import base64, hashlib, os, stat
            from pathlib import Path
            def metadata(value):
                return {'ownerUid':value.st_uid,'mode':format(stat.S_IMODE(value.st_mode),'04o'),
                    'nlink':str(value.st_nlink),'device':str(value.st_dev),'inode':str(value.st_ino),
                    'mtimeNs':str(value.st_mtime_ns),'ctimeNs':str(value.st_ctime_ns)}
            def stable(value):
                return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
                    value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            parent=None; parent_before=None
            if selected['root'] is not None:
                parent=Path(selected['root']); parent_before=parent.lstat()
                if (parent.resolve()!=parent or not stat.S_ISDIR(parent_before.st_mode)
                        or parent_before.st_uid!=os.getuid()
                        or stat.S_IMODE(parent_before.st_mode)!=0o700
                        or Path(selected['path']).resolve()!=Path(selected['path'])):
                    raise ValueError('CLIENT original root custody differs')
            try:
                fd = os.open(selected['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            except FileNotFoundError:
                if not selected['missing']: raise
                print(json.dumps({'missing':True})); raise SystemExit(0)
            try:
                before=os.fstat(fd)
                if selected['terminalPending'] is not None:
                    parent=Path(selected['path']).parent; parent_before=parent.lstat()
                    if (parent.resolve()!=parent or not stat.S_ISDIR(parent_before.st_mode)
                            or parent_before.st_uid!=os.getuid() or stat.S_IMODE(parent_before.st_mode)!=0o700):
                        raise ValueError('terminal private parent differs')
                    if before.st_nlink==2:
                        try:
                            pending=Path(selected['terminalPending']).lstat()
                        except FileNotFoundError:
                            after=os.fstat(fd)
                            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns')
                            if (after.st_nlink!=1 or not stat.S_ISREG(after.st_mode)
                                    or after.st_uid!=os.getuid() or stat.S_IMODE(after.st_mode)!=0o600
                                    or not 0<after.st_size<=selected['maximum']
                                    or any(getattr(before,key)!=getattr(after,key) for key in fields)):
                                raise ValueError('terminal publication transition changed its owned image')
                            # The publisher's unlink changes nlink and ctime.
                            # Accept no bytes here: the original loop next reads
                            # the strict, stable one-link final descriptor.
                            print(json.dumps({'publishing':True})); raise SystemExit(0)
                        if (not stat.S_ISREG(pending.st_mode) or pending.st_uid!=os.getuid()
                                or stat.S_IMODE(pending.st_mode)!=0o600 or pending.st_nlink!=2
                                or (pending.st_dev,pending.st_ino)!=(before.st_dev,before.st_ino)
                                or not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>selected['maximum']):
                            raise ValueError('terminal publication aliases differ')
                        print(json.dumps({'publishing':True})); raise SystemExit(0)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
                        or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
                        or before.st_size>selected['maximum']):
                    raise ValueError('queue private image custody differs')
                with os.fdopen(os.dup(fd),'rb') as reader: body=reader.read(selected['maximum']+1)
                after=os.fstat(fd)
                if stable(before)!=stable(after) or len(body)!=before.st_size: raise ValueError('queue private image changed')
                if parent is not None and stable(parent.lstat())!=stable(parent_before):
                    raise ValueError('CLIENT original root changed during receipt')
                print(json.dumps({'missing':False,'body':base64.b64encode(body).decode(),
                    'custody':{'version':1,'root':selected['root'],'file':selected['path'],
                        'sha256':hashlib.sha256(body).hexdigest(),'byteSize':str(len(body)),
                        'rootMetadata':None if parent_before is None else metadata(parent_before),
                        'fileMetadata':metadata(before),'observerUid':os.getuid()}}))
            finally: os.close(fd)
        """, {"path": path, "maximum": maximum, "missing": missing, "root": root,
              "terminalPending": terminal_pending})
        value = json.loads(raw)
        if terminal_pending is not None and value == {"publishing": True}:
            return None
        if value["missing"]:
            return None
        image = base64.b64decode(value["body"], validate=True)
        custody = value["custody"]
        if (set(value) != {"missing", "body", "custody"}
                or set(custody) != {"version", "root", "file", "sha256", "byteSize",
                                   "rootMetadata", "fileMetadata", "observerUid"}
                or type(custody["version"]) is not int or custody["version"] != 1
                or custody["root"] != root or custody["file"] != path
                or hashlib.sha256(image).hexdigest() != custody["sha256"]
                or str(len(image)) != custody["byteSize"] or len(image) > maximum
                or reference is not None and (reference["sha256"] != custody["sha256"]
                                               or reference["byteSize"] != custody["byteSize"])):
            raise ValueError("received private original commitment differs")
        if retain is not None:
            retain(custody)
        return image

    def install(self, machine, path, raw):
        self.owners["install_direct_guest_file"](machine, self.tools["python"], path, raw)
        # The existing installer is create-only; independently read the result
        # with the stricter private descriptor checks used by this callback.
        received = self.received(machine, path, len(raw))
        if received != raw:
            raise ValueError("installed private observation differs")
        return {"file": path, "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": str(len(raw))}

    def private_parent(self, machine, root):
        self.guest(machine, """
            import os,stat
            from pathlib import Path
            root=Path(selected['root']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
            meta=root.lstat()
            if root.resolve()!=root or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
                raise ValueError('queue private parent differs')
            print('{}')
        """, {"root": root})

    def client_clock(self, case, *, phase=None, receipt_name):
        """Sample only CLIENT's original clock and bracket its actual observer.

        A phase pin names the recorded Python launcher, not its Node child. The
        initial launcher may already be dead during an acknowledged continuation;
        only a supplied current phase is required to be live for this bracket.
        """
        driver = self.tools["queueFaultStagedDriver"]
        selected = {"phase": None if phase is None else phase["process"],
                    "supervisor": self.tools["queueFaultStagedSupervisor"],
                    "supervisorSha256": self.tools["queueFaultStagedSupervisorSha256"],
                    "driver": driver["file"], "driverSha256": driver["sha256"],
                    "python": self.tools["python"]}
        started_mono, started_wall = time.monotonic_ns(), time.time_ns()
        raw = self.guest(self.client, """
            import hashlib,os,re,time
            from pathlib import Path
            def bounded(path,limit):
                with path.open('rb') as file: body=file.read(limit+1)
                if len(body)>limit: raise ValueError('CLIENT clock identity exceeds bound')
                return body
            def pin(pid,expected=None):
                proc=Path('/proc')/str(pid); fields=bounded(proc/'stat',8192).decode().rpartition(') ')[2].split()
                if len(fields)<20 or fields[0]=='Z' or proc.stat().st_uid!=os.getuid():
                    raise ValueError('CLIENT clock process is not live and owned')
                with (proc/'exe').open('rb') as file: executable=hashlib.file_digest(file,'sha256').hexdigest()
                value={'pid':pid,'ownerUid':proc.stat().st_uid,'startTicks':fields[19],
                    'executableSha256':executable,
                    'commandLineSha256':hashlib.sha256(bounded(proc/'cmdline',65536)).hexdigest(),
                    'environmentSha256':hashlib.sha256(bounded(proc/'environ',65536)).hexdigest()}
                if expected is not None and any(value[name]!=expected[name] for name in value):
                    raise ValueError('CLIENT phase launcher changed during clock sample')
                return value
            for name in ('supervisor','driver'):
                body=bounded(Path(selected[name]),262144)
                if hashlib.sha256(body).hexdigest()!=selected[name+'Sha256']:
                    raise ValueError('CLIENT selected continuation source changed')
            observer=pin(os.getpid())
            if (Path('/proc')/str(os.getpid())/'exe').resolve()!=Path(selected['python']).resolve():
                raise ValueError('CLIENT clock observer is not selected AOS Python')
            phase=None if selected['phase'] is None else pin(selected['phase']['pid'],selected['phase'])
            boot=bounded(Path('/proc/sys/kernel/random/boot_id'),64).decode().strip()
            uptime=bounded(Path('/proc/uptime'),128).decode().split()[0]
            if not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot) or not re.fullmatch(r'[0-9]+\\.[0-9]{2}',uptime):
                raise ValueError('CLIENT original clock format differs')
            sampled=str(time.time_ns())
            pin(os.getpid(),observer)
            if phase is not None: pin(phase['pid'],phase)
            print(json.dumps({'version':1,'bootId':boot,'uptimeSeconds':uptime,
                'observedUnixNs':sampled,'observerProcess':observer,'phaseLauncher':phase}))
        """, selected, timeout=5)
        finished_mono, finished_wall = time.monotonic_ns(), time.time_ns()
        value = json.loads(raw)
        if (set(value) != {"version", "bootId", "uptimeSeconds", "observedUnixNs",
                          "observerProcess", "phaseLauncher"}
                or type(value["version"]) is not int or value["version"] != 1
                or not re.fullmatch(r"[0-9]+\.[0-9]{2}", value["uptimeSeconds"])
                or not re.fullmatch(r"[1-9][0-9]{0,19}", value["observedUnixNs"])):
            raise ValueError("CLIENT actual clock receipt differs")
        receipt = {"version": 1, "machine": "CLIENT", "sample": value,
                   "controllerStartedMonotonicNs": str(started_mono),
                   "controllerFinishedMonotonicNs": str(finished_mono),
                   "controllerStartedUnixNs": str(started_wall),
                   "controllerFinishedUnixNs": str(finished_wall),
                   "originalLauncher": case["initial"]["process"],
                   "sourceSelection": selected,
                   "scope": "actual CLIENT observer and optional phase-launcher bracket; no clock authority"}
        retained_reference(case["local"], receipt_name, encoded(receipt))
        return receipt

    def wait_prepared(self, child, guest_root, deadline):
        path = guest_root + "/external_s3/pre-complete-prepared.json"
        while time.time() * 1000 < deadline - 4000:
            raw = self.received(self.client, path, 64 * 1024, missing=True)
            if raw is not None:
                return raw, json.loads(raw)
            # Check only the actual recorded child, not a namespace-wide scan.
            self.guest(self.client, """
                import os
                from pathlib import Path
                p=Path('/proc')/str(selected['pid'])
                fields=(p/'stat').read_text().rpartition(') ')[2].split()
                if fields[0]=='Z' or fields[19]!=selected['startTicks'] or p.stat().st_uid!=selected['ownerUid']:
                    raise ValueError('prepared owner stopped before saved original')
                print('{}')
            """, child)
            time.sleep(0.05)
        raise TimeoutError("saved-original boundary did not arrive within the original cutoff")

    def journal_start(self, pin, run):
        """Bracket the existing successful SQL source marker with the live Native."""
        return json.loads(self.guest(self.native, """
            import hashlib,os,subprocess
            from pathlib import Path
            pin=selected['pin']; proc=Path('/proc')/str(pin['pid'])
            def check():
                fields=(proc/'stat').read_text().rpartition(') ')[2].split()
                if fields[0]=='Z' or fields[19]!=pin['startTicks']: raise ValueError('Native journal lifetime differs')
                with (proc/'exe').open('rb') as file:
                    if hashlib.file_digest(file,'sha256').hexdigest()!=pin['executableSha256']:
                        raise ValueError('Native journal executable differs')
            check()
            result=subprocess.run(['journalctl','--no-pager','--output=json',
                '--output-fields=__CURSOR','--unit=aos-hub.service','-n','1'],
                capture_output=True,check=False,timeout=20)
            rows=result.stdout.splitlines()
            if result.returncode or len(rows)!=1 or len(rows[0])>1048576: raise ValueError('Native journal cursor unavailable')
            cursor=json.loads(rows[0]).get('__CURSOR')
            if not isinstance(cursor,str) or not 0<len(cursor)<=4096: raise ValueError('Native cursor differs')
            check()
            print(json.dumps({**pin,'executablePath':os.readlink(proc/'exe'),'journalCursor':cursor,
                'root':selected['root']}))
        """, {"pin": pin, "root": "/var/lib/hybrid-native-observations/queue-journal-" + run}))

    def journal_finish(self, pin, local):
        root = pin["root"]
        self.private_parent(self.native, root)
        receipt = json.loads(self.guest(self.native, """
            import hashlib,os,subprocess
            from pathlib import Path
            pin=selected; proc=Path('/proc')/str(pin['pid'])
            def check():
                fields=(proc/'stat').read_text().rpartition(') ')[2].split()
                if fields[0]=='Z' or fields[19]!=pin['startTicks'] or os.readlink(proc/'exe')!=pin['executablePath']:
                    raise ValueError('Native journal lifetime differs')
                with (proc/'exe').open('rb') as file:
                    if hashlib.file_digest(file,'sha256').hexdigest()!=pin['executableSha256']:
                        raise ValueError('Native journal executable differs')
            check()
            path=Path(pin['root'])/'selected.jsonl'
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as output:
                result=subprocess.run(['journalctl','--no-pager','--output=json',
                    '--output-fields=__REALTIME_TIMESTAMP,_PID,_EXE,_SYSTEMD_UNIT,MESSAGE',
                    r'--grep=^\\[INFO\\] message=native_application_sql_projection ',
                    '--unit=aos-hub.service','--after-cursor='+pin['journalCursor']],
                    stdout=output,stderr=subprocess.PIPE,check=False,timeout=45)
                output.flush(); os.fsync(output.fileno())
            check()
            if result.returncode or path.stat().st_size>64*1024*1024:
                raise ValueError('Selected SQL marker capture incomplete')
            body=path.read_bytes()
            print(json.dumps({'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),
                'byteSize':str(len(body)),'stderrSha256':hashlib.sha256(result.stderr).hexdigest()}))
        """, pin, timeout=60))
        body = self.received(self.native, receipt["file"], 64 * 1024 * 1024, receipt)
        reference = retained_reference(local, "native-sql-journal.jsonl", body)
        messages = list(self.owners["observed_native_messages"](body.decode(), pin))
        return messages, {"process": pin, "guest": receipt, "received": reference}

    def capture_admission(self, case, context):
        """Run the existing measured SELECT-only reader and real Core observer."""
        local, prepared = case["local"], case["prepared"]
        messages, native_capture = self.journal_finish(case["journal"], local)
        checkpoints = self.owners["native_sql_checkpoints"](messages)
        session = context["admission"]["sessionId"]
        selected = []
        for batch in checkpoints:
            relevant = [row for row in batch["checkpoints"]
                        if row["kind"] == "admission_checked_transaction" and row["sessionId"] == session]
            if relevant:
                # Keep the actual source child's bytes commitment, even when
                # selecting one genuine key from a larger source child.
                selected.append({**batch, "checkpoints": relevant})
        if len(selected) != 1 or len(selected[0]["checkpoints"]) != 1:
            raise ValueError("one source-emitted pre-Complete admission checkpoint is unavailable")
        projection = self.owners["capture_native_sql_projection"](
            self.native, self.database, self.tools, selected,
            self.credentials["operatorReader"], case["journal"],
            database_host=self.tools["nativeDatabaseHost"],
            capture_namespace="queue-fault-" + case["runDigest"])
        if len(projection["observations"]) != 1:
            raise ValueError("measured admission-only SQL observation is unavailable")
        sql = projection["observations"][0]
        image = sql["codecImages"]["admissions"]
        received = [row["controllerReference"] for row in sql["controller"]["receivedImages"]
                    if row["guestReference"] == image]
        if len(received) != 1:
            raise ValueError("SQL codec image has no independently received byte image")
        sql_body = staged.referenced(received[0], MAX_CONTROL)
        public_body = self.received(self.client, case["scopeRoot"] + "/" + prepared["refs"]["beginBody"]["file"],
                                    MAX_CONTROL, {"sha256": prepared["refs"]["beginBody"]["sha256"],
                                                  "byteSize": prepared["refs"]["beginBody"]["bytes"]})
        public = retained_reference(local, "public-begin.json", public_body)
        worker_log, worker_capture = self.owners["retain_direct_log_window"](
            self.worker, self.tools["python"], case["workerBefore"],
            "queue-" + case["runDigest"][:16] + "-admission-worker.log")
        events = faults.runtime.direct_runtime_observations(worker_log.read_text(), case["sourceDigest"])
        control_log, control_capture = self.owners["retain_direct_log_window"](
            self.native, self.tools["python"], case["nativeBefore"],
            "queue-" + case["runDigest"][:16] + "-admission-native.jsonl")
        observations = self.owners["native_control_observations"](control_log.read_text())
        _, bodies = self.owners["capture_direct_native_bodies"](self.native, self.tools, observations, artifact_namespace="queue-fault-" + case["runDigest"])
        candidates = []
        for capture in bodies["bodies"]:
            if (capture["phase"] != "admission" or capture["status"] != 200
                    or any(value is None for value in capture["bodies"].values())):
                continue
            capture = json.loads(json.dumps(capture))
            for reference in capture["bodies"].values():
                reference["file"] = str(Path(reference["file"]).resolve())
                reference["byteSize"] = str(reference["byteSize"])
            manifest = native_faults.admission_codec_manifest(
                capture, public, received[0], self.observer["runtime"]["runtimeCodecRevision"], case["sourceDigest"])
            try:
                faults.authenticated_admission_join(manifest, events, context["admission"])
            except ValueError:
                continue
            candidates.append(manifest)
        if len(candidates) != 1:
            raise ValueError("one actual authenticated protected Admission byte image is unavailable")
        manifest = candidates[0]
        manifest_ref = retained_reference(local, "admission-codec-selection.json", encoded(manifest))
        # The selected wrapper runs native-bodies with the genuine feature ELF.
        # No synthetic result is accepted in place of this process outcome.
        stdout_path, stderr_path = local / "admission-codec.stdout", local / "admission-codec.stderr"
        started = time.time_ns()
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            stdout_path.chmod(0o600); stderr_path.chmod(0o600)
            outcome = subprocess.run([self.observer["wrapper"]["path"], manifest_ref["file"]],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=min(30, max(0.001, case["cutoffUnixMs"] / 1000 - time.time() - 4)), check=False)
        output = staged.private_bytes(stdout_path, MAX_CONTROL)
        errors = staged.private_bytes(stderr_path, 65536)
        execution = {"argv": [self.observer["wrapper"]["path"], manifest_ref["file"]],
                     "startedUnixNs": str(started), "finishedUnixNs": str(time.time_ns()),
                     "exitCode": outcome.returncode, "stderrSha256": hashlib.sha256(errors).hexdigest(),
                     "executable": self.observer["executable"], "wrapper": self.observer["wrapper"]}
        execution_ref = retained_reference(local, "admission-codec-execution.json", encoded(execution))
        if outcome.returncode != 0:
            raise ValueError("actual Core admission observer refused; private diagnostics retained")
        refs = {"codecExecution": execution_ref,
                "codecOutput": {"file": str(stdout_path), "sha256": hashlib.sha256(output).hexdigest(),
                                "byteSize": str(len(output))}, "manifest": manifest_ref,
                "sqlReader": retained_reference(local, "sql-reader.json", encoded(projection)),
                "nativeCapture": retained_reference(local, "native-capture.json",
                    encoded({"journal": native_capture, "controls": control_capture, "bodies": bodies})),
                "workerCapture": retained_reference(local, "worker-capture.json", encoded(worker_capture))}
        return {"manifest": manifest, "manifestSha256": manifest_ref["sha256"],
                "codecStdout": output, "sqlAdmissionsBody": sql_body,
                "authenticatedEvents": events, "references": refs}

    def launch_phase(self, case, phase, selection=None, *, accepted=None,
                     selection_reference=None, selection_root=None,
                     accepted_reference=None, accepted_root=None):
        """Start the actual staged supervisor and retain its real subprocess exit."""
        root = case["guestRoot"] + "/" + phase
        self.private_parent(self.client, root)
        if selection_reference is None:
            if selection is None or accepted_reference is not None:
                raise ValueError("phase has no independently selected original selection")
            selection_ref = self.install(self.client, root + "/selection.json", encoded(selection))
        else:
            if selection is not None or accepted is not None:
                raise ValueError("original-locator continuation cannot reencode its envelopes")
            self.received(self.client, selection_reference["file"], MAX_CONTROL,
                          selection_reference, root=selection_root)
            selection_ref = selection_reference
        argv = [self.tools["python"], self.tools["queueFaultStagedSupervisor"],
                selection_ref["file"], root + "/output"]
        if accepted is None and accepted_reference is None:
            argv.append("--external-pre-complete")
        else:
            if accepted_reference is None:
                ref = self.install(self.client, root + "/accepted-originals.json", encoded(accepted))
            else:
                if accepted_root != case.get("scopeRoot"):
                    raise ValueError("accepted envelope is not in the original CLIENT scope")
                self.received(self.client, accepted_reference["file"], MAX_CONTROL,
                              accepted_reference, root=accepted_root)
                ref = accepted_reference
            argv += ["--continue-accepted", ref["file"]]
        runner = '''import json,os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]); selected=json.loads((root/'invocation.json').read_bytes())
deadline=selected['cutoffUnixMs']/1000-time.time()
if deadline<=0: raise ValueError('original phase deadline expired')
with (root/'stdout.private').open('xb') as out,(root/'stderr.private').open('xb') as err:
    os.chmod(root/'stdout.private',0o600); os.chmod(root/'stderr.private',0o600)
    started=time.time_ns(); child=subprocess.Popen(selected['argv'],stdin=subprocess.DEVNULL,stdout=out,stderr=err)
    timed_out=False
    try: exit_code=child.wait(timeout=deadline)
    except subprocess.TimeoutExpired:
        timed_out=True; exit_code=None
        # The selected supervisor has its own stricter cleanup reserve. A missed
        # terminal remains unknown; this wrapper does not replay its mutation.
    receipt={'argv':selected['argv'],'startedUnixNs':str(started),'finishedUnixNs':str(time.time_ns()),
        'exitCode':exit_code,'timedOut':timed_out,'childPid':child.pid}
    pending=root/'exit.pending'
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(json.dumps(receipt,separators=(',',':')).encode());out.flush();os.fsync(out.fileno())
    os.link(pending,root/'exit.json',follow_symlinks=False);pending.unlink()
'''
        self.install(self.client, root + "/runner.py", runner.encode())
        self.install(self.client, root + "/invocation.json",
                     encoded({"argv": argv, "cutoffUnixMs": case["cutoffUnixMs"]}))
        child = self.owners["launch_managed_process"](self.client, self.tools, root, "phase", [
            self.tools["python"], root + "/runner.py", root], {})
        observed = {"root": root, "output": root + "/output", "process": child,
                    "selectionReference": selection_ref}
        case["initial" if phase == "prepared" else "continuationPhase"] = observed
        retained_reference(case["local"], phase + "-process.json", encoded(child))
        return observed

    def finish_phase(self, case, phase):
        """Retain actual outcome first, including failures and unknown effects."""
        if phase.get("finishAttempted"):
            raise ValueError("phase retention was already attempted; no second capture or mutation")
        phase["finishAttempted"] = True
        while time.time() * 1000 < case["cutoffUnixMs"]:
            raw = self.received(self.client, phase["root"] + "/exit.json", 64 * 1024, missing=True,
                                terminal_pending=phase["root"] + "/exit.pending")
            if raw is not None:
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("staged phase has no actual terminal within original cutoff")
        name = Path(phase["root"]).name
        receipt_ref = retained_reference(case["local"], name + "-exit.json", raw)
        receipt = json.loads(raw)
        for stream in ("stdout", "stderr"):
            body = self.received(self.client, phase["root"] + "/" + stream + ".private", 65536)
            retained_reference(case["local"], name + "-" + stream + ".private", body)
        result_raw = self.received(self.client, phase["output"] + "/external_s3/result.json",
                                   MAX_CONTROL, missing=True)
        if result_raw is not None:
            retained_reference(case["local"], name + "-result.json", result_raw)
        summary_raw = self.received(self.client, phase["output"] + "/summary.json",
                                    MAX_CONTROL, missing=True)
        if summary_raw is not None:
            retained_reference(case["local"], name + "-summary.json", summary_raw)
        return {"receipt": receipt, "receiptReference": receipt_ref,
                "result": None if result_raw is None else json.loads(result_raw),
                "summary": None if summary_raw is None else json.loads(summary_raw)}

    def make_case(self, fault, index, registry, root_bearer, native_pin, *, case):
        run = hashlib.sha256(os.urandom(32)).hexdigest()
        local = self.root / run
        local.mkdir(mode=0o700)
        guest_root = "/var/lib/hybrid-client/queue-faults/" + run
        case.update(fault=fault, index=index, runDigest=run, local=local, guestRoot=guest_root,
                    cutoffUnixMs=selected_deadline(self.tools))
        self.private_parent(self.client, guest_root)
        transport = native_faults.QueueFaultNativeTransport(
            self.client, self.tools, "/var/lib/hybrid-client/queue-faults/case-" + run + ".token",
            self.owners["direct_guest_python"],
            lambda machine, receipt: self.received(machine, receipt["path"], MAX_CONTROL,
                {"sha256": receipt["sha256"], "byteSize": str(receipt["bytes"])}))
        transport.select_browser_bearer(root_bearer,
            lambda path, raw: self.install(self.client, path, raw))
        receipt, whoami = transport.whoami()
        if receipt["status"] != "200":
            raise ValueError("business setup has no actual authenticated actor")
        token = None
        if fault in {"authorization_revoked", "delegation_expired"}:
            owner = whoami["principalKind"] + ":" + whoami["principalRef"]
            # Token issuance is a real reviewed Plan/Apply before the fixed
            # case starts. The following WhoAmI and SQL select its actual actor.
            issued = native_faults.issue_fault_token(self.controls, owner,
                registry["ownerScopeKey"], ["read", "publish"],
                60, "queue-fault-issue-" + str(index))
            path = "/var/lib/hybrid-client/queue-faults/delegation-" + run + ".token"
            self.install(self.client, path, issued["secret"].encode())
            transport = native_faults.QueueFaultNativeTransport(
                self.client, self.tools, path, self.owners["direct_guest_python"],
                lambda machine, receipt: self.received(machine, receipt["path"], MAX_CONTROL,
                    {"sha256": receipt["sha256"], "byteSize": str(receipt["bytes"])}))
            transport.provision()
            receipt, whoami = transport.whoami()
            if receipt["status"] != "200":
                raise ValueError("delegation is not authenticated before original admission")
            token = native_faults.retain_actual_token(self.controls, issued["token"]["tokenId"], registry["ownerScopeKey"])
        deadline = case["cutoffUnixMs"]
        retain = lambda name, body: retained_reference(local, name, body)

        def call(method, request):
            observed, reply = transport.call(method, request)
            if observed["status"] != "200":
                raise ValueError("actual publication setup mutation was not acknowledged; no replay")
            return reply

        business = setup.prepare_publication(call, retain, registry["slug"], run)
        cap_receipt, capabilities = transport.call("DirectUploadService/GetCapabilities", {
            "target": {"kind": "publication", "publicationId": business["target"]["publicationId"]}})
        if cap_receipt["status"] != "200" or capabilities["principalId"] != whoami["principalId"]:
            raise ValueError("actual sealed owner capabilities are not the selected actor")
        cap_raw = self.received(self.client, cap_receipt["path"], MAX_CONTROL,
                               {"sha256": cap_receipt["sha256"], "byteSize": str(cap_receipt["bytes"])})
        cap_ref = self.install(self.client, guest_root + "/capabilities.json", cap_raw)
        actor_ref = self.install(self.client, guest_root + "/whoami.json", encoded(whoami))
        runtime_ref = self.install(self.client, guest_root + "/runtime.json", encoded({
            "artifacts": self.artifacts, "identity": self.identity, "observer": self.observer}))
        scope = {"version": 1, "runId": run, "scope": "external_s3",
            "origin": self.tools["workerUrl"], "tokenFile": transport.jwt_file,
            "providerOrigin": capabilities["profiles"][0]["providerOrigin"],
            "providerPathPrefix": "/" + self.credentials["binding"]["spec"]["s3"]["bucket"] + "/",
            "cutoffUnixMs": deadline, "capabilities": cap_ref,
            "targets": {"complete": {"target": business["target"], "finalReadUrl": None}},
            "reportHelperSource": self.tools["queueFaultReportHelper"],
            "protoSources": self.tools["queueFaultProtoSources"],
            "preComplete": {"actorWhoami": actor_ref, "runtimePins": runtime_ref}}
        scope_ref = self.install(self.client, guest_root + "/scope.json", encoded(scope))
        selection = {"version": 1, "node": self.tools["queueFaultNode"],
            "driver": self.tools["queueFaultStagedDriver"], "scopeSelections": [scope_ref],
            "cutoffUnixMs": deadline}
        case.update({"fault": fault, "index": index, "runDigest": run, "local": local,
                "guestRoot": guest_root, "cutoffUnixMs": deadline, "selection": selection,
                "scope": scope, "sourceDigest": self.identity["identity"]["sourceDigest"],
                "transport": transport, "whoami": whoami, "token": token,
                "registry": registry, "business": business})
        case["workerBefore"] = self.owners["direct_log_position"](
            self.worker, self.tools["python"], self.process["logFile"])
        case["nativeBefore"] = self.owners["direct_log_position"](
            self.native, self.tools["python"], "/var/lib/hybrid-native-observations/requests.jsonl")
        case["journal"] = self.journal_start(native_pin, run)
        case["initial"] = self.launch_phase(case, "prepared", selection)
        raw, prepared = self.wait_prepared(case["initial"]["process"], case["initial"]["output"], deadline)
        case["scopeRoot"] = case["initial"]["output"] + "/external_s3"
        case["preparedRaw"], case["prepared"] = raw, prepared
        retained_reference(local, "prepared-original.json", raw)
        return case


    def install_wrapper(self, case, selection):
        """Install one named fixture graph around the exact current module bytes."""
        root = "/var/lib/hybrid-worker/queue-faults/" + case["runDigest"]
        self.private_parent(self.worker, root)
        expected = {"compiledSourceDigest": case["sourceDigest"], "modules": {}}
        for name, tool in (("shim.mjs", "shim"), ("index.wasm", "wasm")):
            path = Path(self.tools[tool])
            expected["modules"][name] = {"bytes": path.stat().st_size,
                "sha256": self.artifacts["files"][tool]["sha256"]}
        installed = self.artifacts["distributionStorePath"]
        raw = self.guest(self.worker, """
            import hashlib,importlib.util,os
            from pathlib import Path
            config=Path(selected['process']['configurationFile'])
            fd=os.open(config,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as file: body=file.read(1048577)
            if len(body)>1048576 or hashlib.sha256(body).hexdigest()!=selected['process']['configurationSha256']:
                raise ValueError('Original Worker configuration changed')
            original=json.loads(body)
            if original['scriptPath']!=selected['installed']+'/shim.mjs':
                raise ValueError('Wrapper source is not the actual installed Worker')
            module=Path(selected['module'])
            spec=importlib.util.spec_from_file_location('selected_queue_modules',module)
            helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
            observed=helper.prepare_queue_fault_modules(selected['installed'],selected['expected'],
                selected['selection'],Path(selected['root'])/'modules')
            options=dict(original);options['scriptPath']=observed['scriptPath']
            options['queueFaultCaptureSelection']={
                'version':1,'binding':'REGISTRY_BUCKET',
                'prefix':selected['selection']['capture']['prefix'],
                'runDigest':selected['selection']['runDigest'],
                'sourceDigest':selected['selection']['sourceDigest'],
                'cutoffUnixMs':selected['selection']['capture']['cutoffUnixMs']}
            image=json.dumps(options,separators=(',',':')).encode()
            path=Path(selected['root'])/'configuration.json'
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out: out.write(image);out.flush();os.fsync(out.fileno())
            observed.update(configurationFile=str(path),configurationSha256=hashlib.sha256(image).hexdigest(),
                selection=selected['selection'],originalConfigurationSha256=selected['process']['configurationSha256'])
            print(json.dumps(observed))
        """, {"root": root, "process": self.process, "expected": expected,
              "installed": installed, "selection": selection, "module": self.tools["queueFaultModules"]})
        wrapper = json.loads(raw)
        case["wrapper"], case["workerRoot"] = wrapper, root
        case["priorWorkerStopAttempted"] = True
        stopped = self.owners["stop_direct_worker"](self.worker, self.tools["python"], self.process)
        case["priorWorkerStopped"] = True
        retained_reference(case["local"], "prior-worker-disposal.json", encoded(stopped))
        case["wrapperLaunchAttempted"] = True
        self.process = self.owners["start_direct_worker"](
            self.worker, self.tools, wrapper["configurationFile"], "queue-fault-" + str(case["index"]))
        case["wrapperProcess"] = self.process
        wrapper["process"] = self.process
        return wrapper

    def start_collector(self, case, wrapper, cutoff):
        """Start the existing process-envelope collector before any continuation."""
        observed, _ = self.owners["observe_direct_runtime_process"](
            self.worker, self.tools, self.process["generation"], process=self.process)
        process = observed["processes"]["workerd"]
        remaining = cutoff / 1000 - time.time() - 5
        if remaining <= 1:
            raise TimeoutError("original collector has no remaining owned window")
        root = case["workerRoot"] + "/collector"
        self.private_parent(self.worker, root)
        arguments = [self.tools["python"], self.tools["queueFaultInvocationResources"],
            "--pid", str(process["pid"]), "--executable", self.tools["workerd"],
            "--start-ticks", str(process["startTicks"]), "--duration-seconds", str(min(60, remaining)),
            "--interval-millis", "100", "--output", root + "/window.json"]
        # The collector creates its output before collecting. Only a source-
        # owned subprocess terminal makes that image eligible for retention.
        runner = '''import json,os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]); selected=json.loads((root/'invocation.json').read_bytes())
started=time.time_ns(); exit_code=None; timed_out=False
try:
    result=subprocess.run(selected['argv'],stdin=subprocess.DEVNULL,
        timeout=max(0.001,selected['cutoffUnixMs']/1000-time.time()),check=False)
    exit_code=result.returncode
except subprocess.TimeoutExpired:
    timed_out=True
receipt={'version':1,'argv':selected['argv'],'startedUnixNs':str(started),
    'finishedUnixNs':str(time.time_ns()),'exitCode':exit_code,'timedOut':timed_out}
pending=root/'exit.pending'
fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as out:
    out.write(json.dumps(receipt,separators=(',',':')).encode());out.flush();os.fsync(out.fileno())
os.link(pending,root/'exit.json',follow_symlinks=False);pending.unlink()
'''
        self.install(self.worker, root + "/runner.py", runner.encode())
        self.install(self.worker, root + "/invocation.json",
                     encoded({"argv": arguments, "cutoffUnixMs": cutoff}))
        owner = self.owners["launch_managed_process"](
            self.worker, self.tools, root, "collector",
            [self.tools["python"], root + "/runner.py", root], {})
        collector = {"owner": owner, "path": root + "/window.json", "workerd": process,
                     "terminalPath": root + "/exit.json", "arguments": arguments,
                     "runnerSha256": hashlib.sha256(runner.encode()).hexdigest(),
                     "cutoffUnixMs": cutoff, "durationSeconds": min(60, remaining)}
        case["collector"] = collector
        retained_reference(case["local"], "collector-start.json", encoded(collector))
        return collector

    def finish_collector(self, case):
        if case.get("collectorFinishAttempted"):
            raise ValueError("collector retention was already attempted")
        case["collectorFinishAttempted"] = True
        collector = case["collector"]
        while time.time() * 1000 < case["cutoffUnixMs"]:
            raw = self.received(self.worker, collector["terminalPath"], 64 * 1024, missing=True,
                                terminal_pending=str(Path(collector["terminalPath"]).with_name("exit.pending")))
            if raw is not None:
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("original process collector has no retained terminal")
        terminal_ref = retained_reference(case["local"], "collector-exit.json", raw)
        terminal = json.loads(raw)
        if (set(terminal) != {"version", "argv", "startedUnixNs", "finishedUnixNs", "exitCode", "timedOut"}
                or terminal["version"] != 1 or terminal["argv"] != collector["arguments"]):
            raise ValueError("actual collector terminal differs from its selected invocation")
        body = self.received(self.worker, collector["path"], 8 * 1024 * 1024, missing=True)
        image_ref = None if body is None else retained_reference(case["local"], "process-window.json", body)
        receipt = {"terminal": terminal_ref, "window": image_ref, "owner": collector["owner"]}
        if terminal["exitCode"] != 0 or terminal["timedOut"] is not False or body is None:
            raise ValueError("actual collector failed or is unknown; terminal retained first")
        return json.loads(body), receipt

    def wrapper_log(self, case):
        """Read the selected current log; never infer delivery from capture traffic."""
        body = self.received(self.worker, self.process["logFile"], 16 * 1024 * 1024)
        lines = body.decode().splitlines()
        captures = []
        for line in lines:
            prefix = "direct_queue_job_capture "
            offset = line.find(prefix)
            if offset < 0:
                continue
            if len(line.encode()) > 4096:
                raise ValueError("queue capture metadata exceeds its closed bound")
            row = faults.runtime._direct_runtime_closed_json(line[offset + len(prefix):])
            fields = {"version", "sourceDigest", "runDigest", "invocationDigest", "jobDigest",
                      "rawSha256", "rawBytes", "key", "atMillis", "state",
                      "capturePutReturned", "queueServerAcceptance"}
            if (set(row) != fields or row["version"] != 1
                    or row["runDigest"] != case["runDigest"] or row["sourceDigest"] != case["sourceDigest"]
                    or not RUN.fullmatch(row["jobDigest"]) or not RUN.fullmatch(row["rawSha256"])
                    or not re.fullmatch(r"[1-9][0-9]{0,4}", row["rawBytes"])
                    or int(row["rawBytes"]) > 65536
                    or row["key"] != ".aos-queue-fault-capture/" + case["runDigest"] + "/" + row["jobDigest"] + ".json"
                    or row["queueServerAcceptance"] is not None):
                raise ValueError("actual capture metadata changed its selected original")
            captures.append(row)
        return body, captures

    def export_job(self, case, context, row):
        """Export only the actual selected R2 image through its recorded runner."""
        raw = self.guest(self.worker, """
            import hashlib,os,socket,stat,struct
            from pathlib import Path
            pin=selected['process'];proc=Path('/proc')/str(pin['pid'])
            def check():
                fields=(proc/'stat').read_text().rpartition(') ')[2].split()
                command=(proc/'cmdline').read_bytes().split(b'\\x00')[:-1]
                if fields[0]=='Z' or fields[19]!=pin['startTicks'] or proc.stat().st_uid!=pin['ownerUid'] or command!=[os.fsencode(value) for value in pin['arguments']]:
                    raise ValueError('queue image runner lifetime changed')
                config=Path(pin['configurationFile']).read_bytes()
                if len(config)>1048576 or hashlib.sha256(config).hexdigest()!=pin['configurationSha256']:
                    raise ValueError('queue image runner configuration changed')
            check();path=Path('/var/lib/hybrid-worker/acceptance-control.sock')
            metadata=path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=pin['ownerUid'] or stat.S_IMODE(metadata.st_mode)!=0o600:
                raise ValueError('queue image control socket custody differs')
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(10)
            try:
                sock.connect(str(path))
                peer_pid,peer_uid,_=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if peer_pid!=pin['pid'] or peer_uid!=pin['ownerUid']:
                    raise ValueError('queue image receiver is not selected runner')
                sock.sendall(json.dumps(selected['request'],separators=(',',':')).encode());sock.shutdown(socket.SHUT_WR)
                parts=[];size=0
                while True:
                    part=sock.recv(4096)
                    if not part:break
                    size+=len(part)
                    if size>98304:raise ValueError('queue image export exceeds bound')
                    parts.append(part)
                reply=json.loads(b''.join(parts))
            finally:sock.close()
            check();print(json.dumps(reply))
        """, {"process": self.process, "request": {"version": 1, "kind": "queue-fault-job-read",
                "runDigest": case["runDigest"], "sourceDigest": case["sourceDigest"],
                "jobDigest": row["jobDigest"]}}, timeout=15)
        exported = faults.runtime._direct_runtime_closed_json(raw)
        body = base64.b64decode(exported["base64"], validate=True)
        if (exported["eof"] is not True or len(body) != int(row["rawBytes"])
                or exported["byteSize"] != row["rawBytes"]
                or exported["sha256"] != row["rawSha256"]
                or hashlib.sha256(body).hexdigest() != row["rawSha256"]
                or exported["jobDigest"] != row["jobDigest"] or exported["key"] != row["key"]
                or exported["sourceDigest"] != case["sourceDigest"] or exported["runDigest"] != case["runDigest"]
                or exported["configurationSha256"] != self.process["configurationSha256"]
                or exported["runnerPid"] != self.process["pid"]
                or exported["runnerStartTicks"] != self.process["startTicks"]
                or exported["queueServerAcceptance"] is not None):
            raise ValueError("actual PUT and private queue image export commitments differ")
        job = faults.runtime._direct_runtime_closed_json(body.decode())
        if (set(job) != {"version", "admission", "complete", "placementId", "closed"}
                or job["version"] != 1 or job["admission"] != context["admission"]
                or job["complete"] != context["complete"]
                or job["placementId"] != case["prepared"]["placement"]["placementId"]
                or job["closed"] is None or faults.canonical_digest(job) != row["jobDigest"]):
            raise ValueError("actual SDK queue argument is not the Core-checked admitted original")
        image = retained_reference(case["local"], "actual-queue-job.json", body)
        exported.pop("base64")
        receipt = retained_reference(case["local"], "actual-queue-job-export.json", encoded(exported))
        return job, {"image": image, "export": receipt, "capturePut": row,
                     "independentQueueCodecValidation": None, "queueServerAcceptance": None}

    def prepare_dispatch(self, case):
        prepared = case["prepared"]
        def read_ref(name):
            item = prepared["refs"][name]
            return self.received(self.client, case["scopeRoot"] + "/" + item["file"], MAX_CONTROL,
                {"sha256": item["sha256"], "byteSize": item["bytes"]}, root=case["scopeRoot"])
        request = {"fault": case["fault"], "status": prepared["status"],
                   "publicBeginBody": read_ref("beginBody"), "completeBody": read_ref("completeBody"),
                   "placementId": prepared["placement"]["placementId"],
                   "sourceDigest": case["sourceDigest"], "runDigest": case["runDigest"],
                   "cutoffUnixMs": case["cutoffUnixMs"]}
        sequence = case["index"] * 8
        def admission(session):
            receipt = native_faults.capture_admission_sql(self.native, self.tools,
                self.owners["direct_guest_python"], session, sequence)
            retained_reference(case["local"], "admission-sql-receipt.json", encoded(receipt))
            return self.received(self.native, receipt["path"], MAX_CONTROL,
                {"sha256": receipt["sha256"], "byteSize": str(receipt["bytes"])})
        def whoami():
            receipt, reply = case["transport"].whoami()
            if receipt["status"] != "200" or reply != case["whoami"]:
                raise ValueError("actor changed before actual saved Complete admission")
            return reply
        def configure(context):
            if case["fault"] != "conditional_source_replacement":
                return None
            placement = next(item for item in context["admission"]["placements"]
                             if item["placementId"] == prepared["placement"]["placementId"])
            path = "/" + self.credentials["binding"]["spec"]["s3"]["bucket"] + "/" + placement["stagingPrefix"]
            path += "/" + hashlib.sha256(context["admission"]["sessionId"].encode()).hexdigest()
            path += "/" + placement["placementId"] + "/payload"
            selected = {"version": 1, "runDigest": case["runDigest"], "host": "s3.fleet.test",
                        "path": path, "sourceSha256": case["business"]["sourceSha256"],
                        "fullObjectBytes": "8388608",
                        "cutoffUnixMs": min(case["cutoffUnixMs"], int(time.time() * 1000) + 20000)}
            reply = setup.get_owner_command(self.s3, self.tools, self.owners,
                self.tools["queueFaultGetInstallation"], {"kind": "arm", "selection": selected})
            if reply.get("status") != "armed":
                raise ValueError("exact provider GET owner did not arm; no Complete sent")
            case["getSelection"] = selected
            return retained_reference(case["local"], "get-arm.json", encoded({"selection": selected, "reply": reply}))
        callback = faults.run_precomplete_queue_fault(request, read_admission=admission,
            read_whoami=whoami, capture_admission_projection=lambda context: self.capture_admission(case, context),
            install_wrapper=lambda selection: self.install_wrapper(case, selection),
            start_collector=lambda wrapper, cutoff: self.start_collector(case, wrapper, cutoff),
            configure_fault=configure,
            retain_private=lambda name, value: retained_reference(case["local"], name, encoded(value)))
        case["context"] = callback["context"]
        refs = {}
        for name in ("admissionObservation", "wrapperObservation"):
            ref = callback[name]
            body = Path(ref["file"]).read_bytes()
            if hashlib.sha256(body).hexdigest() != ref["sha256"] or str(len(body)) != ref["byteSize"]:
                raise ValueError("saved actual callback observation changed before guest install")
            refs[name] = self.install(self.client, case["scopeRoot"] + "/" + name + ".json", body)
        continuation = staged.continuation_record(prepared, case["preparedRaw"], refs)
        self.install(self.client, case["scopeRoot"] + "/pre-complete-continuation.json", encoded(continuation))
        return callback

    def replace_held_source(self, case, context, job):
        """Replace only the actual signed source held by the selected GET owner."""
        held = setup.get_owner_command(self.s3, self.tools, self.owners,
            self.tools["queueFaultGetInstallation"], {"kind": "observe"})
        current = held.get("held")
        if (not isinstance(current, dict) or current.get("released") is not False
                or current.get("disconnected") is not False
                or current.get("runDigest") != case["runDigest"]
                or current.get("sourceSha256") != case["business"]["sourceSha256"]
                or current.get("fullObjectBytes") != case["business"]["byteSize"]
                or current.get("pathSha256") != hashlib.sha256(case["getSelection"]["path"].encode()).hexdigest()
                or current.get("method") != "GET"):
            return {"state": "unavailable", "reason": "actual_selected_get_not_held", "qualification": None}
        retained_reference(case["local"], "actual-held-get.json", encoded(held))
        receipt = native_faults.capture_pending_sql(self.native, self.tools,
            self.owners["direct_guest_python"], context["admission"]["sessionId"],
            context["complete"]["operationId"], case["index"] * 8 + 1)
        body = self.received(self.native, receipt["path"], MAX_CONTROL,
            {"sha256": receipt["sha256"], "byteSize": str(receipt["bytes"])})
        pending = native_faults.pending_snapshot(body, context["admission"], context["complete"])
        retained_reference(case["local"], "replacement-server-intent.json", encoded({"receipt": receipt, "pending": pending}))
        # The signed condition is obtained from the actual incoming GET, never
        # guessed before close. The independent adapter verifies full old bytes.
        response = self.guest(self.worker, """
            import importlib.util,os
            from pathlib import Path
            spec=importlib.util.spec_from_file_location('selected_garage',selected['module'])
            adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
            root=Path(selected['root']);root.mkdir(mode=0o700,exist_ok=False)
            credential=adapter._private_file(Path('/var/lib/hybrid-worker/provider-observation/credential.json'),4096)
            original=json.loads(credential)
            if set(original)!={'access_key','secret_key','region'} or original['region']!='garage':
                raise ValueError('Actual selected Garage credential shape differs')
            converted=json.dumps({'accessKeyId':original['access_key'],'secretAccessKey':original['secret_key']}).encode()
            adapter._create(root/'credential.json',converted)
            transport=adapter.GarageSigV4(selected['curl'],'https://s3.fleet.test','garage',
                root/'credential.json',root/'transport',selected['cutoffUnixMs'])
            replace=adapter.GarageReplacement(transport,selected['admission'],selected['placementId'],
                {'etag':selected['ifMatch'],'providerVersion':selected['providerVersion']},selected['runDigest'])
            result=replace.replace_once(root/'replacement-pending.json')
            adapter._create(root/'outcome.json',json.dumps(result,separators=(',',':')).encode())
            print(json.dumps({'result':result,'path':str(root/'outcome.json'),
                'scope':'actual SigV4 instrumentation; no production consumer outcome inferred'}))
        """, {"module": self.tools["queueFaultGarage"], "root": case["workerRoot"] + "/replacement",
              "curl": __import__("shlex").split(self.tools["curl"])[0], "cutoffUnixMs": case["getSelection"]["cutoffUnixMs"],
              "admission": job["admission"], "placementId": job["placementId"],
              "ifMatch": current["ifMatch"], "providerVersion": current["providerVersion"],
              "runDigest": case["runDigest"]}, timeout=20)
        observed = json.loads(response)
        retained_reference(case["local"], "garage-replacement.json", encoded(observed))
        return observed["result"]

    def accepted_original(self, case, observed):
        """Select the actual first saved response without changing guest locators."""
        result = observed["result"]
        if (observed["receipt"]["exitCode"] != 2 or observed["receipt"]["timedOut"] is not False
                or not isinstance(result, dict) or result.get("mode") != "pre_complete_handoff"
                or result.get("status") != "incomplete" or len(result.get("results", [])) != 1):
            return None
        first = result["results"][0]
        if first.get("observedStates") == ["committed"]:
            return None
        response = first.get("firstCompleteResponse")
        if (not isinstance(response, dict) or set(response) != {"file", "bytes", "sha256"}
                or first.get("firstCompleteCallIndex") != 1
                or first.get("preparedCompleteSha256") != case["prepared"]["refs"]["completeBody"]["sha256"]):
            raise ValueError("actual first Complete sidecar does not name the original")
        prepared = {"file": case["scopeRoot"] + "/pre-complete-prepared.json",
                    "sha256": hashlib.sha256(case["preparedRaw"]).hexdigest(),
                    "byteSize": str(len(case["preparedRaw"]))}
        ref = {"file": case["scopeRoot"] + "/" + response["file"],
               "sha256": response["sha256"], "byteSize": response["bytes"]}
        ClientPreparedIO(self, case).read_reference(ref, case["scopeRoot"], MAX_CONTROL)
        accepted = {"version": 1, "originals": [{"scope": "external_s3", "prepared": prepared, "firstResponse": ref}]}
        case["acceptedReference"] = self.install(self.client,
            case["scopeRoot"] + "/accepted-originals.json", encoded(accepted))
        return case["acceptedReference"]

    def run_case(self, fault, index, registry, root_bearer, native_pin):
        """Drive one fresh business original; unknown phases never activate replay."""
        case = {}
        previous = self.process
        output = {"fault": fault, "state": "unavailable", "qualification": None,
                  "consumerAuthorityQualification": None, "providerRedispatch": None,
                  "publicationCommit": "not_invoked", "resource2GiBAssessment": None,
                  "foregroundBudgetComparison": None}
        try:
            self.make_case(fault, index, registry, root_bearer, native_pin, case=case)
            output["runDigest"] = case["runDigest"]
            self.prepare_dispatch(case)
            context = case["context"]
            # Capture is instrumentation, not acceptance. Poll only this real
            # wrapper's bounded metadata until its actual selected job appears.
            deadline = min(case["cutoffUnixMs"] / 1000 - 5, time.time() + 10)
            while True:
                _, rows = self.wrapper_log(case)
                positive = [row for row in rows if row["state"] == "captured" and row["capturePutReturned"] is True]
                if len(positive) == 1:
                    break
                if len(positive) > 1 or rows or time.time() >= deadline:
                    raise ValueError("actual selected queue capture is absent, refused or unknown")
                time.sleep(0.05)
            job, output["actualJob"] = self.export_job(case, context, positive[0])
            output["selectedJobDigest"] = positive[0]["jobDigest"]
            if fault == "conditional_source_replacement":
                try:
                    output["replacement"] = self.replace_held_source(case, context, job)
                finally:
                    output["getRelease"] = setup.get_owner_command(self.s3, self.tools, self.owners,
                        self.tools["queueFaultGetInstallation"], {"kind": "release", "runDigest": case["runDigest"]})
            initial = self.finish_phase(case, case["initial"])
            case["initialFinished"] = True
            output["initialPhase"] = initial
            if fault in {"authorization_revoked", "delegation_expired"}:
                # Invalidation follows actual first dispatch/job. This tests
                # same-original promotion refusal only, not consumer revocation.
                if self.accepted_original(case, initial) is None:
                    output["reason"] = "no_known_pending_original_for_actor_invalidation"
                else:
                    if fault == "authorization_revoked":
                        invalidation = native_faults.retire_actual_token(self.controls,
                            case["token"]["tokenId"], registry["ownerScopeKey"], "queue-fault-retire-" + str(index))
                        receipt, after = case["transport"].whoami()
                        invalidation = {"retirement": invalidation, "whoamiReceipt": receipt,
                                        "whoamiCode": after.get("code")}
                        if receipt["status"] != "403" or after.get("code") != "permission_denied":
                            raise ValueError("actual retired original actor was not refused")
                    else:
                        invalidation = native_faults.wait_actual_token_expiry(case["transport"], case["whoami"],
                            case["token"], self.controls, registry["ownerScopeKey"],
                            maximum_seconds=min(65, case["cutoffUnixMs"] / 1000 - time.time() - 5))
                    output["actorInvalidation"] = invalidation
                    adapter = ClientPreparedIO(self, case)
                    adapter.within_original(case["prepared"], min(self.tools["fleetCutoffMonotonic"],
                        time.monotonic() + max(0, case["cutoffUnixMs"] / 1000 - time.time())))
                    try:
                        adapter.continue_acknowledged(case["initial"]["selectionReference"]["file"],
                            case["acceptedReference"]["file"], case["guestRoot"] + "/accepted/output")
                    except ValueError:
                        # Actual exit/summary are retained by the adapter first.
                        # A missing or generic denial cannot prove consumer auth.
                        output["reason"] = "known_original_progression_refused_or_unknown"
                    else:
                        raise ValueError("invalidated actor unexpectedly completed original promotion")
                    output["state"] = "observed_invalidation_with_progression_unknown"
            elif fault == "conditional_source_replacement":
                output["state"] = output["replacement"]["state"]
                output["reason"] = output["replacement"].get("reason")
            resources, output["collectorReceipt"] = self.finish_collector(case)
            log, _ = self.wrapper_log(case)
            retained_reference(case["local"], "actual-worker-window.private", log)
            wrappers = faults.fault_observations(log.decode(), case["sourceDigest"], case["runDigest"])
            events = faults.runtime.direct_runtime_observations(log.decode(), case["sourceDigest"])
            selected = faults.selected_queue_events(events, context["original"])
            output["productionEvents"] = selected
            try:
                output["invocationResources"] = faults.single_invocation_resources(
                    resources, wrappers, events, context["original"])
            except (ValueError, AssertionError):
                output["invocationResources"] = None
            if fault in {"enqueue_ack_lost", "completion_ack_lost"}:
                output["ackLoss"] = faults.assert_ack_loss_observed(wrappers, positive[0]["jobDigest"], fault)
                output["state"] = "actual_ack_loss_observed_effect_unknown"
                if fault == "completion_ack_lost":
                    try:
                        output["retainedReadReplay"] = faults.assert_retained_read_replay(
                            events, context["original"], positive[0]["jobDigest"], wrappers)
                    except AssertionError:
                        output["retainedReadReplay"] = None
            output["scope"] = "actual separate 8MiB production original; unavailable downstream/provider/consumer facts stay null"
        except Exception as error:
            output["state"] = "unknown" if case is not None and "context" in case else "unavailable"
            output["failureClass"] = type(error).__name__
            output["reason"] = "selected_original_prerequisite_or_observation_incomplete"
        finally:
            if "local" in case:
                cleanup_failures = []
                def cleanup(name, action):
                    try:
                        output[name] = action()
                        return True
                    except Exception as error:
                        cleanup_failures.append({"operation": name, "failureClass": type(error).__name__})
                        return False

                if "getSelection" in case and "getRelease" not in output:
                    cleanup("getRelease", lambda: setup.get_owner_command(self.s3, self.tools, self.owners,
                        self.tools["queueFaultGetInstallation"], {"kind": "release", "runDigest": case["runDigest"]}))
                # Never interrupt/restart the original driver to make a new
                # attempt. Its selected supervisor must reach its own terminal.
                if "initial" in case and not case["initial"].get("finishAttempted"):
                    cleanup("initialPhase", lambda: self.finish_phase(case, case["initial"]))
                if "continuationPhase" in case and not case["continuationPhase"].get("finishAttempted"):
                    cleanup("continuationPhase", lambda: self.finish_phase(case, case["continuationPhase"]))
                if "collector" in case and not case.get("collectorFinishAttempted"):
                    cleanup("collectorCleanup", lambda: self.finish_collector(case))
                if "wrapperProcess" in case:
                    def stop_wrapper():
                        stopped = self.owners["stop_direct_worker"](self.worker, self.tools["python"], self.process)
                        retained_reference(case["local"], "wrapper-disposal.json", encoded(stopped))
                        return stopped
                    if cleanup("wrapperDisposal", stop_wrapper):
                        def restore_worker():
                            self.process = self.owners["start_direct_worker"](self.worker, self.tools,
                                previous["configurationFile"], "queue-restore-" + str(index))
                            return self.process
                        cleanup("workerRestoration", restore_worker)
                elif case.get("priorWorkerStopped") and not case.get("wrapperLaunchAttempted"):
                    def restore_before_launch():
                        self.process = self.owners["start_direct_worker"](self.worker, self.tools,
                            previous["configurationFile"], "queue-restore-" + str(index))
                        return self.process
                    cleanup("workerRestoration", restore_before_launch)
                elif case.get("wrapperLaunchAttempted") or case.get("priorWorkerStopAttempted"):
                    # A launch/stop with no returned owner cannot authorize a
                    # namespace scan, another stop, or a replacement process.
                    cleanup_failures.append({"operation": "workerOwner", "failureClass": "UnknownProcessOutcome"})
                output["cleanupFailures"] = cleanup_failures
                if cleanup_failures:
                    output["state"] = "unknown"
                    output["reason"] = "owned_cleanup_or_retention_incomplete"
                retained_reference(case["local"], "case-outcome.json", encoded(output))
        return output


def run_production_queue_fault_window(client, native, worker, s3, database, tools,
                                     controls, credentials, artifacts, identity,
                                     process, publication, owners):
    """Call all five ordinary production originals after the full publication.

    This supplementary ledger cannot qualify the main corpus or current runtime
    from its smaller objects. Original deadlines and every unknown remain intact.
    """
    window = ProductionQueueWindow(client, native, worker, s3, database, tools,
        controls, credentials, artifacts, identity, process, owners)
    registry = publication["queueFaultRegistry"]["registry"]
    selected_registry = {"slug": registry["slug"], "ownerScopeKey": credentials["organization"]["ownerScopeKey"]}
    token = owners["direct_root_browser_token"](client, tools["curl"], tools["python"],
        owners["private_guest_command"], reuse_session=True)
    native_pin = publication["storageWorkflowCaptures"]["nativeProcess"]
    cases = {}
    fault_names = ("enqueue_ack_lost", "completion_ack_lost",
                   "conditional_source_replacement", "authorization_revoked", "delegation_expired")
    for index, fault in enumerate(fault_names):
        cases[fault] = window.run_case(fault, index, selected_registry, token, native_pin)
        if cases[fault].get("cleanupFailures"):
            for remaining in fault_names[index + 1:]:
                cases[remaining] = {"state": "unavailable", "reason": "prior_owned_cleanup_unknown",
                                    "qualification": None}
            break
    report = {"version": 1, "cases": cases, "qualification": None,
              "nativeBulkBytes": None, "resource2GiBAssessment": None,
              "scope": "called supplementary production queue windows; main full corpus/resources remain separate"}
    retained_reference(window.root, "outcome.json", encoded(report))
    if any(case.get("cleanupFailures") for case in cases.values()):
        raise RuntimeError("production queue window owner cleanup is unknown; later mutations refused")
    return report, window.process



class ClientPreparedIO:
    """Read and continue one actual CLIENT original without moving its locators.

    This adapter owns private file/process custody only. Admission, actor,
    provider and SQL validation remain separate selected caller prerequisites.
    """

    def __init__(self, window, case, *, current_phase=None):
        self.window, self.case, self.current_phase = window, case, current_phase
        self.ordinal = 0

    def next_name(self, purpose):
        self.ordinal += 1
        return "client-%04d-%s.json" % (self.ordinal, purpose)

    def read_reference(self, reference, original_guest_scope_root, maximum):
        """Return actual private CLIENT bytes plus a separately retained custody receipt."""
        roots = {self.case["guestRoot"], self.case["scopeRoot"], self.case["initial"]["root"]}
        if (original_guest_scope_root not in roots or not isinstance(reference, dict)
                or set(reference) != {"file", "sha256", "byteSize"}
                or not isinstance(reference["sha256"], str)
                or not RUN.fullmatch(reference["sha256"])
                or not isinstance(reference["byteSize"], str)
                or not re.fullmatch(r"0|[1-9][0-9]{0,8}", reference["byteSize"])
                or int(reference["byteSize"]) > maximum):
            raise ValueError("CLIENT original reference or selected root differs")
        file = reference["file"]
        if not isinstance(file, str):
            raise ValueError("CLIENT original locator is not a path")
        if not file.startswith("/"):
            file = original_guest_scope_root + "/" + file
        return self.window.received(self.window.client, file, maximum, reference,
            root=original_guest_scope_root,
            retain=lambda custody: retained_reference(self.case["local"],
                self.next_name("read-custody"), encoded(custody)))

    def within_original(self, prepared, controller_deadline_monotonic_seconds):
        """Require fresh CLIENT boot/uptime and independent controller cutoffs.

        The printed uptime resolution and full observer round trip are added
        conservatively. This sample grants neither clock authority nor renewal;
        the actual Native child independently checks immediately before dispatch.
        """
        from decimal import Decimal

        original_raw = self.read_reference({
            "file": self.case["scopeRoot"] + "/pre-complete-prepared.json",
            "sha256": hashlib.sha256(self.case["preparedRaw"]).hexdigest(),
            "byteSize": str(len(self.case["preparedRaw"]))}, self.case["scopeRoot"], MAX_CONTROL)
        if prepared != json.loads(original_raw) or prepared != self.case["prepared"]:
            raise ValueError("CLIENT clock selected a different original")
        if (not isinstance(controller_deadline_monotonic_seconds, (int, float))
                or isinstance(controller_deadline_monotonic_seconds, bool)
                or controller_deadline_monotonic_seconds > self.window.tools["fleetCutoffMonotonic"]
                or time.monotonic() >= controller_deadline_monotonic_seconds
                or time.time() * 1000 >= prepared["cutoffUnixMs"]):
            raise TimeoutError("original controller deadline expired or extended")
        receipt = self.window.client_clock(self.case, phase=self.current_phase,
                                          receipt_name=self.next_name("clock"))
        sample = receipt["sample"]
        elapsed = (Decimal(receipt["controllerFinishedMonotonicNs"])
                   - Decimal(receipt["controllerStartedMonotonicNs"])) / Decimal(1000000000)
        latest_ms = (Decimal(sample["uptimeSeconds"]) + Decimal("0.01") + elapsed) * 1000
        if (sample["bootId"] != prepared["clock"]["bootId"]
                or latest_ms >= prepared["clock"]["cutoffUptimeMs"]
                or time.monotonic() >= controller_deadline_monotonic_seconds
                or time.time() * 1000 >= prepared["cutoffUnixMs"]):
            raise TimeoutError("actual CLIENT original boot or conservative cutoff differs")

    def continue_acknowledged(self, selection_file, accepted_originals_file, fresh_output):
        """Continue only the existing original selection and create-only accepted envelope."""
        original_selection = self.case["initial"]["selectionReference"]
        accepted = self.case.get("acceptedReference")
        if (selection_file != original_selection["file"] or accepted is None
                or accepted_originals_file != accepted["file"]
                or fresh_output != self.case["guestRoot"] + "/accepted/output"):
            raise ValueError("CLIENT acknowledged continuation locators differ")
        self.read_reference(original_selection, self.case["initial"]["root"], MAX_CONTROL)
        self.read_reference(accepted, self.case["scopeRoot"], MAX_CONTROL)
        phase = self.window.launch_phase(self.case, "accepted",
            selection_reference=original_selection, selection_root=self.case["initial"]["root"],
            accepted_reference=accepted, accepted_root=self.case["scopeRoot"])
        self.current_phase = phase
        observed = self.window.finish_phase(self.case, phase)
        self.current_phase = None
        receipt, summary, result = observed["receipt"], observed["summary"], observed["result"]
        # Exit 2 deliberately means a normally retained incomplete observation
        # in this supervisor. It is never full race or publication qualification.
        if (receipt["exitCode"] != 2 or receipt["timedOut"] is not False
                or not isinstance(summary, dict)
                or set(summary) != {"status", "scopes", "mode", "publicationCommit",
                                    "raceQualification", "cleanupSettlement", "windowsAAndC"}
                or summary["status"] != "incomplete"
                or summary["scopes"] != ["external_s3"]
                or summary["mode"] != "accepted_original_continuation"
                or summary["publicationCommit"] != "not_invoked"
                or summary["raceQualification"] is not None
                or summary["cleanupSettlement"] is not None
                or summary["windowsAAndC"] != "not_executed"
                or not isinstance(result, dict)
                or result.get("mode") != "accepted_original_continuation"
                or result.get("status") != "incomplete"
                or result.get("publicationCommit") != "not_invoked"
                or not isinstance(result.get("results"), list) or len(result["results"]) != 1
                or result["results"][0].get("terminalState") != "committed"
                or result["results"][0].get("raceQualification") is not None):
            raise ValueError("acknowledged original progression is unknown or incomplete; no further mutation")
        return observed
