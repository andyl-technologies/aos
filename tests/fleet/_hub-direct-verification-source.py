"""Prepare the real small signed source for the required verification timeout.

The ordinary APR release and verifier produce the source. The initial observer
selects the actual tiny helper NAR through its real narinfo before final Worker
observations. It never predicts a session ID, version or verification outcome.
"""

import hashlib
import json
import re


def direct_verification_observer_selection(staging_prefix, original):
    """Bind one bounded source to the actual installed private staging domain."""
    if (not isinstance(staging_prefix, str)
            or ".aos-direct-qualification" not in staging_prefix.split("/")
            or not staging_prefix.endswith("/.aos-direct-upload")
            or any(part in {"", ".", ".."} for part in staging_prefix.split("/"))
            or re.search(r"[%?#\\\s]", staging_prefix)
            or not isinstance(original, dict) or set(original) != {"file", "relativePath", "sha256", "byteSize"}
            or not isinstance(original["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", original["sha256"]) is None
            or type(original["byteSize"]) is not int or not 1 <= original["byteSize"] <= 65536):
        raise ValueError("Verification observer source or current staging prefix differs")
    return {"version": 1, "stagingPrefix": staging_prefix,
        "expectedSourceSha256": original["sha256"], "expectedSourceBytes": str(original["byteSize"])}


def prepare_direct_verification_source(client, tools, organization_slug):
    """Retain the genuine helper NAR before configuring its verification observer."""
    if not isinstance(organization_slug, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", organization_slug) is None:
        raise ValueError("Verification source organization identity differs")
    source = prepare_direct_signed_surface(client, tools["python"], tools["apr"], tools["git"],
        tools["opensshBin"], tools["nixBin"], tools["helperStorePath"],
        tools["workerUrl"] + "/" + organization_slug + "/read-timeout",
        publication_project=tools["publicationProject"], authoring_name="external-timeout")
    selected = json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, re, stat
        from pathlib import Path

        root=Path(selected['source']['surfaceRoot'])
        helper=Path(selected['helperStorePath'])
        if helper.parent!=Path('/nix/store') or re.fullmatch(r'[0-9abcdfghijklmnpqrsvwxyz]{32}-.+',helper.name) is None:
            raise ValueError('Selected helper is not an exact store root')
        # A genuine source closure may contain hundreds of narinfos. Read only
        # the helper's exact cache key, then verify its authenticated StorePath.
        candidates=[root/(helper.name.split('-',1)[0]+'.narinfo')]

        def read_stable(path,maximum):
            descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=maximum:
                    raise ValueError('Selected actual source is not a bounded regular file')
                body=stream.read(maximum+1); after=os.fstat(stream.fileno())
            if len(body)!=before.st_size or any(getattr(before,field)!=getattr(after,field)
                    for field in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Actual timeout source changed during initial selection')
            return body

        matching=[]
        for path in candidates:
            narinfo=read_stable(path,65536)
            lines=narinfo.decode().splitlines()
            stores=[line.removeprefix('StorePath: ') for line in lines if line.startswith('StorePath: ')]
            if stores!=[selected['helperStorePath']]:
                continue
            urls=[line.removeprefix('URL: ') for line in lines if line.startswith('URL: ')]
            if len(urls)!=1:
                raise ValueError('Actual helper narinfo URL is missing or ambiguous')
            relative=urls[0]
            if (not relative.startswith('nar/') or re.search(r'[%?#\\\\\\s]',relative)
                    or any(part in {'','.', '..'} for part in relative.split('/'))):
                raise ValueError('Actual helper NAR URL is not one confined relative path')
            content=root/relative
            if not content.resolve().is_relative_to(root.resolve()):
                raise ValueError('Actual helper NAR escaped its signed surface')
            body=read_stable(content,65536)
            matching.append({'original':{'file':str(content),'relativePath':relative,
                'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body)},
                'narinfo':{'file':str(path),'sha256':hashlib.sha256(narinfo).hexdigest(),
                    'byteSize':len(narinfo),'storePath':selected['helperStorePath']}})
        if len(matching)!=1:
            raise ValueError('Ordinary signed source has no unique small actual helper NAR')
        print(json.dumps(matching[0]))
    """, {"source": source, "helperStorePath": tools["helperStorePath"]}))
    original = selected["original"]
    body = read_direct_guest_file(client, tools["python"], original["file"], 65536)
    if len(body) != original["byteSize"] or hashlib.sha256(body).hexdigest() != original["sha256"]:
        raise ValueError("Actual signed verification source changed during retention")
    prepared = {"version": 1, "source": source, "original": original, "narinfo": selected["narinfo"],
        "registryName": "read-timeout", "organizationSlug": organization_slug}
    retain_direct_flow("provider-timeout-initial-signed-source.json", prepared)
    return prepared


def publish_direct_verification_source(client, tools, registry_slug, prepared, token):
    """Run one ordinary publisher and retain its actual terminal without a verdict."""
    if (not isinstance(registry_slug, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}/read-timeout", registry_slug) is None
            or not isinstance(token, str) or not token
            or prepared["organizationSlug"] + "/read-timeout" != registry_slug):
        raise ValueError("Verification publisher registry or browser identity differs")
    source = prepared["source"]
    original = prepared["original"]
    arguments = [tools["aos"], "--json", "hub", "registry", "publish", "upload", registry_slug,
        "--root", source["surfaceRoot"], "--hub", tools["workerUrl"], "--token", token,
        "--direct-provider-policy", tools["providerPolicyFile"],
        "--direct-upload-journal", source["publisherHome"] + "/timeout-direct-upload.sqlite"]
    return json.loads(direct_guest_python(client, tools["python"], """
        import hashlib, os, stat, subprocess, time
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['source']['publisherHome'])/'verification-invocation'
        root.mkdir(mode=0o700,exist_ok=False)
        original=selected['original']
        descriptor=os.open(original['file'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(descriptor,'rb') as source:
            before=os.fstat(source.fileno()); body=source.read(65537)
            after=os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_size!=original['byteSize']
                or len(body)!=original['byteSize']
                or hashlib.sha256(body).hexdigest()!=original['sha256']
                or any(getattr(before,name)!=getattr(after,name) for name in
                    ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))):
            raise ValueError('Selected verification original changed before normal publication')
        environment=dict(os.environ)
        home=selected['source']['publisherHome']
        environment.update(XDG_CONFIG_HOME=home+'/.config',
            XDG_DATA_HOME=home+'/.local/share',XDG_CACHE_HOME=home+'/.cache',
            SSL_CERT_FILE='/etc/ssl/certs/ca-certificates.crt')

        def retain(name,body):
            descriptor=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
            return {'file':str(root/name),'sha256':hashlib.sha256(body).hexdigest(),
                'byteSize':str(len(body))}

        arguments=selected['arguments']
        invocation=retain('invocation.private.json',json.dumps({'arguments':arguments,
            'environment':environment},sort_keys=True,separators=(',',':')).encode())
        started=time.time_ns()
        with (root/'stdout.private').open('xb') as stdout, (root/'stderr.private').open('xb') as stderr:
            try:
                completed=subprocess.run(arguments,env=environment,stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,timeout=180,check=False)
                terminal={'exitCode':completed.returncode,'timedOut':False}
            except subprocess.TimeoutExpired:
                terminal={'exitCode':None,'timedOut':True}
            stdout.flush(); os.fsync(stdout.fileno())
            stderr.flush(); os.fsync(stderr.fileno())
        finished=time.time_ns()
        outputs={}
        for name in ('stdout','stderr'):
            path=root/(name+'.private')
            with path.open('rb') as stream:
                metadata=os.fstat(stream.fileno())
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            outputs[name]={'file':str(path),'sha256':digest,'byteSize':str(metadata.st_size)}
        document={'version':1,**terminal,'startedUnixNs':str(started),
            'finishedUnixNs':str(finished),'registrySlug':selected['registrySlug'],
            'sourceCommit':selected['source']['sourceCommit'],'invocation':invocation,
            'outputs':outputs,'remoteDrain':None}
        retain('terminal.json',json.dumps(document,sort_keys=True,separators=(',',':')).encode())
        print(json.dumps(document))
    """, {"source": source, "original": original, "arguments": arguments,
        "registrySlug": registry_slug}, timeout=195))
