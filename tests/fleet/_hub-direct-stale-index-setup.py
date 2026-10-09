"""Connect the retained index original to the selected five-machine workload.

The transparent listener starts unarmed before baseline and loaded publication
traffic. Its one selected fault uses real Native SQL, the ordinary index command
and the existing public placement plan. This module supplies no Hub authority.
"""

import hashlib
import json
from pathlib import Path


def install_direct_stale_index_path(native, tools):
    """Start the fixed listener using actual resolved TLS file observations."""
    selected = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        files = {}
        for name, original in selected.items():
            path = Path(original).resolve(strict=True)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 2*1024*1024:
                    raise ValueError('Held-index TLS selection is not a bounded actual file')
                body = source.read(2*1024*1024+1)
                after = os.fstat(source.fileno())
            if len(body)!=before.st_size or any(getattr(before, field)!=getattr(after, field)
                    for field in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Held-index TLS selection changed during observation')
            files[name] = {'path':str(path),'sha256':hashlib.sha256(body).hexdigest(),
                'byteSize':str(len(body))}
        print(json.dumps(files))
    """, {"certificateFile": tools["issuerCertificate"],
        "privateKeyFile": tools["issuerPrivateKey"],
        "caFile": "/etc/ssl/certs/ca-certificates.crt"}))
    configuration = {"version": 1, "root": "/var/lib/hybrid-native-stale-index",
        "listenPort": 4650, "upstreamHost": "worker", "upstreamPort": 443,
        "originHost": "aos.fleet.test", "holdModuleFile": tools["staleIndexHold"],
        **{name: reference["path"] for name, reference in selected.items()}}
    controller = managed_fixture_module(tools["staleIndexController"], "direct_stale_index")
    installed = controller.start_direct_stale_index_listener(native, tools, configuration)
    retain_direct_flow("held-index-listener-installation.json", {
        "tlsFiles": selected, "configuration": configuration, "installation": installed,
    })
    return installed


class DirectStaleIndexSql:
    """Retain bounded real SELECT results from the original Native database."""

    def __init__(self, native, tools, *, label="held-index"):
        if label not in {"held-index", "read-revision"}:
            raise ValueError("Index SQL observation label differs")
        self.label = label
        self.native = native
        self.tools = tools
        self.sequence = 0

    def __call__(self, query):
        if (not isinstance(query, str) or not query.startswith("SELECT ")
                or len(query.encode()) > 32768 or any(marker in query for marker in (";", "--", "/*"))):
            raise ValueError("Held-index query must be a bounded single actual SELECT")
        self.sequence += 1
        if self.sequence > 128:
            raise ValueError("Held-index SQL observation bound exceeded")
        observed = json.loads(direct_guest_python(self.native, self.tools["python"], """
            import hashlib, os, subprocess
            from pathlib import Path
            from urllib.parse import urlsplit

            root = Path('/var/lib/hybrid-native-stale-index/sql')
            if selected['label'] != 'held-index':
                root = root / selected['label']
            root.mkdir(mode=0o700, exist_ok=True)
            database = Path(selected['database']).read_text().strip()
            parsed = urlsplit(database)
            if (len(database.encode())>4096 or parsed.scheme!='postgresql' or not parsed.hostname
                    or parsed.password is not None or parsed.query or parsed.fragment):
                raise ValueError('Held-index PostgreSQL URL contains unsupported credential material')
            query = "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
            query += "SET LOCAL statement_timeout='20s'; SELECT COALESCE(json_agg(row_to_json(row)), '[]') "
            query += "FROM ("+selected['query']+") row; COMMIT;"
            path = root/(str(selected['sequence'])+'.private.json')
            descriptor = os.open(path,
                os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor,'wb') as output:
                result = subprocess.run([selected['psql'],'-d',database,'-X','-qAt','-v','ON_ERROR_STOP=1','-c',query],
                    stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.PIPE,
                    timeout=25,check=False)
                output.flush()
                os.fsync(output.fileno())
            if result.returncode or not 0 < path.stat().st_size <= 8*1024*1024:
                raise ValueError('Actual held-index SELECT refused or exceeded bound')
            body=path.read_bytes()
            rows=json.loads(body)
            if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):
                raise ValueError('Actual held-index SQL row shape differs')
            print(json.dumps({'rows':[list(row.values()) for row in rows], 'receipt':{
                'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body),
                'querySha256':hashlib.sha256(query.encode()).hexdigest(),'exitCode':result.returncode,
                'stderrSha256':hashlib.sha256(result.stderr).hexdigest()}}))
        """, {"sequence": self.sequence, "query": query,
            "database": self.tools["nativeDatabaseUrlFile"], "label": self.label,
            "psql": self.tools["postgres"] + "/psql"}, timeout=35))
        retain_direct_flow(self.label + "-sql-" + str(self.sequence) + ".json", observed)
        return observed["rows"]


def qualify_direct_stale_index(native, worker, client, database_machine, tools,
                              controls, registry, source, worker_process, artifacts):
    """Hold one ordinary index read and require the real current-SQL commit fence."""
    digest = observe_direct_native_trust(native, tools, artifacts, "held-index")
    original = Path("external-direct-flow/native-trust-held-index.json").read_bytes()
    if hashlib.sha256(original).hexdigest() != digest:
        raise ValueError("Held-index Native process observation changed")
    native_process = json.loads(original)
    controller = managed_fixture_module(tools["staleIndexController"], "direct_stale_index_case")
    environment = controller.capture_direct_stale_index_environment(native, tools, native_process,
        tools["staleIndexInstallation"]["root"] + "/native.environment")
    query = DirectStaleIndexSql(native, tools)
    selected_tools = {**tools, "aosHub": tools["hub"],
        "staleIndexSqlQuery": query,
        "staleIndexReadIndex": lambda slug: registry_index_observations(query, slug),
        "staleIndexRetain": retain_direct_flow,
        "staleIndexControllerRoot": str(Path("external-direct-flow/held-index-original").resolve()),
        "staleIndexEnvironmentCapture": environment}
    return controller.run_direct_stale_index_case(native, worker, client, database_machine,
        selected_tools, controls, registry, source, worker_process)
