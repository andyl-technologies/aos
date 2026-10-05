"""Retain and serve the ordinary small signed fixture for real Mirror calls.

Source bytes originate in APR on the client. Transfers are checked against an
independently retained inventory, and the Worker upstream has its own recorded
Nginx lifetime. Public read captures stay private and never traverse Native as a
host-side source-body substitute.
"""

import hashlib
import json
import re
import shlex
import time


MIRROR_SOURCE_FILE_LIMIT = 1024 * 1024
MIRROR_SOURCE_TOTAL_LIMIT = 64 * 1024 * 1024


def mirror_upstream_configuration(run_id, root, tools):
    """Constrain the selected TLS upstream to this run's transferred surface."""
    if (not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or root != "/var/lib/hybrid-worker/mirror-upstream/" + run_id
            or any(not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._=-]+/[A-Za-z0-9._/-]+", tools[name])
                or any(part in {"", ".", ".."} for part in tools[name].split("/")[1:])
                for name in ("issuerCertificate", "issuerPrivateKey", "nginx"))):
        raise ValueError("Mirror upstream leaves its selected source-built TLS inputs")
    return (
        "worker_processes 1;\npid " + root + "/nginx.pid;\n"
        "error_log " + root + "/nginx-error.private;\nevents { worker_connections 64; }\n"
        "http {\n    log_format mirror '$request_method $uri $status $body_bytes_sent';\n"
        "    access_log " + root + "/access.private mirror;\n"
        "    server {\n        listen 4778 ssl;\n        server_name aos.andyl.org;\n"
        "        ssl_certificate " + tools["issuerCertificate"] + ";\n"
        "        ssl_certificate_key " + tools["issuerPrivateKey"] + ";\n"
        "        location /fleet-mirror/" + run_id + "/ {\n"
        "            alias " + root + "/surface/;\n            autoindex off;\n        }\n"
        "        location / { return 404; }\n    }\n}\n"
    )


def prepare_external_mirror_signed_source(client, tools, run_id):
    """Use APR's actual signed helper release without extending the large corpus."""
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("Mirror signed source requires its actual run")
    upstream = "https://aos.andyl.org:4778/fleet-mirror/" + run_id
    signed = prepare_direct_signed_surface(client, tools["python"], tools["apr"], tools["git"],
        tools["opensshBin"], tools["nixBin"], tools["helperStorePath"], upstream,
        authoring_name="mirror-" + run_id[:16])
    captured = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, re, stat
        from pathlib import Path

        root=Path(selected['signed']['surfaceRoot'])
        if root.is_symlink() or root.resolve()!=root or not root.is_dir():
            raise ValueError('Mirror signed surface lacks its actual private root')
        rows=[]; total=0; pair=None
        for directory,dirs,files in os.walk(root,followlinks=False):
            if any((Path(directory)/name).is_symlink() for name in dirs):
                raise ValueError('Mirror signed surface contains a directory link')
            for name in sorted(files):
                path=Path(directory)/name
                descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(descriptor,'rb') as source:
                    before=os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode) or not 0<=before.st_size<=selected['fileLimit']:
                        raise ValueError('Mirror signed source exceeds its small fixture file bound')
                    sha=hashlib.file_digest(source,'sha256').hexdigest()
                    after=os.fstat(source.fileno())
                if any(getattr(before,key)!=getattr(after,key) for key in
                        ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                    raise ValueError('Mirror signed source changed during retention')
                relative=path.relative_to(root).as_posix()
                if len(rows)>=4096 or len(relative.encode())>512:
                    raise ValueError('Mirror signed source exceeds its complete path bound')
                total+=before.st_size
                if total>selected['totalLimit']:
                    raise ValueError('Mirror signed source exceeds its complete small fixture byte bound')
                rows.append({'path':relative,'sha256':sha,'byteSize':before.st_size})
                if re.fullmatch(r'[0-9a-z]{32}\\.narinfo',relative):
                    text=path.read_text()
                    stores=[line[11:] for line in text.splitlines() if line.startswith('StorePath: ')]
                    if stores==[selected['helperStorePath']]:
                        urls=[line[5:] for line in text.splitlines() if line.startswith('URL: ')]
                        if pair is not None or len(urls)!=1:
                            raise ValueError('Mirror helper governing narinfo is ambiguous')
                        pair=[relative,urls[0]]
        rows.sort(key=lambda row:row['path'])
        by_path={row['path']:row for row in rows}
        if pair is None or any(path not in by_path for path in pair):
            raise ValueError('Mirror helper has no actual governing narinfo/NAR pair')
        print(json.dumps({'version':1,'objects':rows,'pullObjects':[by_path[path] for path in pair],
            'totalBytes':total,'sourceCommit':selected['signed']['sourceCommit']}))
    """, {"signed": signed, "helperStorePath": tools["helperStorePath"],
        "fileLimit": MIRROR_SOURCE_FILE_LIMIT, "totalLimit": MIRROR_SOURCE_TOTAL_LIMIT}))
    if captured["sourceCommit"] != signed["sourceCommit"]:
        raise ValueError("Mirror source inventory changed the actual signed source commit")
    require_mirror_source_inventory(captured["objects"])
    require_mirror_source_inventory(captured["pullObjects"], mode="pull_through")
    return {"signed": signed, "inventory": captured, "upstream": upstream, "runId": run_id}


def install_external_mirror_upstream(client, worker, tools, source, ownership):
    """Transfer the exact small source and record one owned upstream process."""
    run_id = source["runId"]
    root = "/var/lib/hybrid-worker/mirror-upstream/" + run_id
    rows = require_mirror_source_inventory(source["inventory"]["objects"])
    transferred = []
    for row in rows.values():
        if row["byteSize"] > MIRROR_SOURCE_FILE_LIMIT:
            raise ValueError("Mirror transfer exceeds its separately bounded small source")
        raw = read_direct_guest_file(client, tools["python"],
            source["signed"]["surfaceRoot"] + "/" + row["path"], MIRROR_SOURCE_FILE_LIMIT)
        if len(raw) != row["byteSize"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Mirror transfer source changed from its retained signed inventory")
        installed = install_direct_guest_file(worker, tools["python"], root + "/surface/" + row["path"], raw)
        if installed["sha256"] != row["sha256"] or installed["byteSize"] != row["byteSize"]:
            raise ValueError("Mirror upstream transfer differs from independently retained source bytes")
        transferred.append(installed)
    configuration = mirror_upstream_configuration(run_id, root, tools).encode()
    reference = install_direct_guest_file(worker, tools["python"], root + "/nginx.conf", configuration)
    arguments = [tools["nginx"], "-e", root + "/nginx-error.private", "-c", reference["file"],
        "-p", root + "/", "-g", "daemon off;"]
    observation = {"invocationObservationMode": "nginx_linux_master_title",
        "configurationFile": reference["file"], "configurationSha256": reference["sha256"],
        "expectedMasterTitle": "nginx: master process " + " ".join(arguments)}
    process = launch_managed_process(worker, tools, root, "upstream", arguments, {}, nginx_observation=observation)
    ownership["mirrorUpstream"] = {"root": root, "process": process}
    return {"root": root, "process": process, "configuration": reference, "transferred": transferred,
        "upstream": source["upstream"], "scope": "actual signed fixture upstream; destination effects not inferred"}


def stop_external_mirror_upstream(worker, tools, ownership):
    """Stop only the recorded upstream lifetime and retain its observed exit."""
    selected = ownership.get("mirrorUpstream")
    if selected is None:
        return None
    exited = stop_external_oci_process(worker, tools, selected["root"], selected["process"], "upstream")
    ownership["mirrorUpstream"] = None
    return {"process": selected["process"], "exit": exited, "providerSettlement": None}


def read_external_mirror_visible(client, tools, selection, rows, refresh, capture_root, *, cutoff):
    """Retain actual protected registry GET bodies through the current Worker."""
    if (not re.fullmatch(r"/var/lib/hybrid-client/external-oci/[0-9a-f]{32}/mirror-reads/[a-z][a-z0-9-]{0,31}", capture_root)
            or tools["workerUrl"] != "https://localhost:4673"):
        raise ValueError("Mirror public read leaves the current paired fixture")
    require_mirror_source_inventory(rows, mode=selection["mode"])
    token = refresh()
    remaining = cutoff - time.monotonic()
    if remaining <= 0:
        raise ValueError("Mirror public reads reached the original fixture cutoff")
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, subprocess, time
        from pathlib import Path
        from urllib.parse import quote

        os.umask(0o077)
        root=Path(selected['captureRoot']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
        credential=root/'authorization.private'
        credential.write_text('Authorization: Bearer '+selected['token']+'\\n')
        observations=[]
        deadline=time.monotonic()+selected['remainingSeconds']
        for index,row in enumerate(selected['rows']):
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise ValueError('Mirror selected public read cutoff expired')
            leaf=root/str(index); leaf.mkdir(mode=0o700)
            body=leaf/'body.private'; headers=leaf/'headers.private'; stderr=leaf/'stderr.private'
            url=selected['origin']+'/'+selected['registrySlug']+'/'+quote(row['path'],safe='/')
            arguments=selected['curl']+['-sS','--max-time',str(min(60,remaining)),'--max-filesize',str(max(row['byteSize'],1)),
                '--request','GET','-H','@'+str(credential),'-D',str(headers),'-o',str(body),'-w','%{http_code}',url]
            with stderr.open('xb') as errors:
                reply=subprocess.run(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                    stderr=errors,timeout=min(65,remaining),check=False)
            if reply.returncode or reply.stdout!=b'200' or not body.is_file():
                raise ValueError('Actual protected Mirror read refused; private captures retained')
            with body.open('rb') as stream:
                sha=hashlib.file_digest(stream,'sha256').hexdigest()
            count=body.stat().st_size
            if count!=row['byteSize'] or sha!=row['sha256']:
                raise ValueError('Actual Mirror delivery changed its signed source bytes')
            observations.append({'path':row['path'],'httpStatus':200,'sha256':sha,'byteSize':count,
                'privateCapture':{'file':str(body),'sha256':sha,'byteSize':count,
                    'headersFile':str(headers),'stderrFile':str(stderr)}})
        print(json.dumps(observations))
    """, {"captureRoot": capture_root, "origin": tools["workerUrl"],
        "registrySlug": selection["registrySlug"], "rows": rows, "token": token,
        "curl": shlex.split(tools["curl"]), "remainingSeconds": remaining}, timeout=remaining))
