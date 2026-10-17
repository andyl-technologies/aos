"""Capture the real serving role and finite private inputs for Mirror review.

The review tool runs on Native so its live process checks use the correct PID
namespace. Worker inputs are copied by exact byte commitment into that private
root; their original files and journals remain untouched.
"""

import hashlib
import json
import re


def mirror_review_reference(reference):
    """Translate an actual retained file into the reviewer's closed selector."""
    path = reference.get("file", reference.get("path"))
    size = reference["byteSize"]
    if (not isinstance(path, str) or not path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            or re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is None
            or isinstance(size, bool) or not str(size).isdigit() or int(size) < 1):
        raise ValueError("Mirror review reference is not an actual bounded file")
    return {"path": path, "sha256": reference["sha256"], "byteSize": int(size)}


def capture_external_mirror_native(native, tools, prepared, helper):
    """Retain installed derivation identities and the actual original helper."""
    coordinates = prepared["coordinates"]
    root = coordinates["nativeRoot"] + "/mirror-review"
    value = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
        def digest_file(filename):
            path=Path(filename)
            with path.open('rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=536870912:
                    raise ValueError('Mirror actual tuple file exceeds bound')
                sha=hashlib.file_digest(stream,'sha256').hexdigest()
                after=os.fstat(stream.fileno())
            if any(getattr(before,k)!=getattr(after,k) for k in
                    ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Mirror tuple file changed during capture')
            return {'file':str(path),'sha256':sha,'byteSize':before.st_size}
        def tuple_file(filename):
            path=Path(filename)
            if len(path.parts)<4 or path.parts[:3]!=('/','nix','store'):
                raise ValueError('Mirror tuple is not an immutable store file')
            store=Path(*path.parts[:4])
            result=subprocess.run([selected['nixStore'],'--query','--deriver',str(store)],
                capture_output=True,check=False,timeout=20)
            deriver=result.stdout.decode().strip()
            if result.returncode or not deriver.startswith('/nix/store/') or not deriver.endswith('.drv'):
                raise ValueError('Mirror tuple has no actual registered deriver')
            return {**digest_file(path),'storePath':str(store),'deriver':deriver}
        process=selected['process']; proc=Path('/proc')/str(process['pid'])
        before=(proc/'stat').read_text().rpartition(') ')[2].split()
        argv=(proc/'cmdline').read_bytes()
        if (before[0]=='Z' or before[19]!=process['startTicks']
                or proc.stat().st_uid!=process['ownerUid'] or len(argv)>65536
                or hashlib.sha256(argv).hexdigest()!=process['commandLineSha256']
                or argv.split(b'\\x00')[:-1]!=[os.fsencode(v) for v in process['arguments']]):
            raise ValueError('Mirror Native original process differs')
        serving=tuple_file(selected['files']['nativeServing'])
        if digest_file(proc/'exe')['sha256']!=serving['sha256'] or serving['sha256']!=process['executableSha256']:
            raise ValueError('Mirror serving process is not the selected helper')
        input_ref=digest_file(selected['input']); readiness_ref=digest_file(selected['readiness'])
        if input_ref['sha256']!=selected['inputSha256']:
            raise ValueError('Mirror producer original helper input changed')
        ready=json.loads(Path(selected['readiness']).read_bytes())
        if (ready['scope']!='controlled_external_oci_native_origin'
                or ready['identity']['pid']!=process['pid']
                or str(ready['identity']['startTicks'])!=process['startTicks']
                or ready['identity']['inputSha256']!=input_ref['sha256']):
            raise ValueError('Mirror producer readiness names another actual epoch')
        manifest={'version':1,'commonSourceStorePath':selected['commonSource'],
            'workerSourceStorePath':selected['workerSource'],
            'nativeSourceStorePath':selected['nativeSource'],
            'workerDistributionStorePath':selected['distribution'],
            'workerSourceDigest':hashlib.sha256(os.fsencode(selected['workerSource'])).hexdigest(),
            'nativeServingRole':'controlled_external_oci_native_origin','nativeServing':serving}
        manifest['workerScriptVersion']='emulated-'+manifest['workerSourceDigest']
        for name,path in selected['files'].items():
            if name!='nativeServing': manifest[name]=tuple_file(path)
        observed={'version':1,'role':'controlled_external_oci_native_origin',
            'pid':process['pid'],'startTicks':process['startTicks'],'ownerUid':process['ownerUid'],
            'executableSha256':serving['sha256'],'arguments':process['arguments'],
            'commandLineSha256':hashlib.sha256(argv).hexdigest(),
            'commonSourceStorePath':selected['commonSource'],'workerSourceStorePath':selected['workerSource'],
            'servingStorePath':serving['storePath'],'servingDeriver':serving['deriver'],
            'inputSha256':input_ref['sha256'],'readinessSha256':readiness_ref['sha256']}
        retained={}
        for name,document in (('manifest',manifest),('native-observation',observed)):
            path=root/(name+'.json'); raw=json.dumps(document,separators=(',',':')).encode()
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'wb') as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            retained[name]=digest_file(path)
        after=(proc/'stat').read_text().rpartition(') ')[2].split()
        if after[0]=='Z' or after[19]!=before[19]:
            raise ValueError('Mirror Native original process changed during tuple capture')
        print(json.dumps({'manifest':manifest,'nativeObservation':observed,
            'manifestFile':retained['manifest'],'nativeObservationFile':retained['native-observation'],
            'nativeInput':input_ref,'nativeReadiness':readiness_ref,
            'nixStoreExecutable':digest_file(selected['nixStore'])}))
    """, {"root": root, "nixStore": tools["nixStore"], "process": helper["process"],
        "input": helper["input"]["file"], "inputSha256": helper["input"]["sha256"],
        "readiness": helper["inputValue"]["readinessFile"],
        "commonSource": tools["commonSourceStorePath"], "workerSource": tools["workerSourcePath"],
        "nativeSource": tools["nativeSourcePath"], "distribution": tools["workerDistribution"],
        "files": {"nativeServing": tools["managedCleanupNativeHelper"], "normalNative": tools["hub"],
            "wasm": tools["wasm"], "script": tools["shim"], "runner": tools["runner"],
            "runtimeExecutable": tools["workerd"], "providerConformance": tools["providerConformance"]}}, timeout=240))
    return value


def copy_external_mirror_review_file(native, worker, tools, root, name, source, maximum):
    """Copy exact original Worker bytes while retaining their original locator."""
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name) is None:
        raise ValueError("Mirror private copy label differs")
    raw = read_direct_guest_file(worker, tools["python"], source, maximum)
    if not raw:
        raise ValueError("Mirror private input is empty")
    copied = install_direct_guest_file(native, tools["python"], root + "/inputs/" + name, raw)
    if copied["sha256"] != hashlib.sha256(raw).hexdigest() or copied["byteSize"] != len(raw):
        raise ValueError("Mirror private input copy differs")
    return {"originalFile": source, "retained": mirror_review_reference(copied)}


def copy_external_mirror_provider_journal(native, worker, tools, root, journal):
    """Retain one bounded complete private journal without replaying provider I/O."""
    inventory = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path
        root=Path(selected['journal']); rows=[]; total=0
        if root.is_symlink() or root.resolve()!=root or not root.is_dir():
            raise ValueError('Mirror provider journal root differs')
        for directory,dirs,files in os.walk(root,followlinks=False):
            if any((Path(directory)/name).is_symlink() for name in dirs):
                raise ValueError('Mirror provider journal has a linked directory')
            for name in sorted(files):
                path=Path(directory)/name
                descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(descriptor,'rb') as source:
                    before=os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode) or not 0<=before.st_size<=16777216:
                        raise ValueError('Mirror provider journal file exceeds bound')
                    digest=hashlib.file_digest(source,'sha256').hexdigest(); after=os.fstat(source.fileno())
                if any(getattr(before,k)!=getattr(after,k) for k in
                        ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                    raise ValueError('Mirror provider journal changed')
                total+=before.st_size
                relative=path.relative_to(root).as_posix()
                if len(rows)>=4096 or len(relative.encode())>512 or total>134217728:
                    raise ValueError('Mirror complete provider journal exceeds bound')
                rows.append({'path':relative,'sha256':digest,'byteSize':before.st_size})
        if not rows: raise ValueError('Mirror provider journal is empty')
        print(json.dumps({'files':rows,'byteSize':total}))
    """, {"journal": journal}, timeout=120))
    destination = root + "/provider-journal"
    for row in inventory["files"]:
        raw = read_direct_guest_file(worker, tools["python"], journal + "/" + row["path"], 16777216)
        if len(raw) != row["byteSize"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Mirror provider journal changed before private transfer")
        copied = install_direct_guest_file(native, tools["python"], destination + "/" + row["path"], raw)
        if copied["sha256"] != row["sha256"] or copied["byteSize"] != row["byteSize"]:
            raise ValueError("Mirror provider journal copy differs")
    return {"originalDirectory": journal, "retainedDirectory": destination, **inventory}
