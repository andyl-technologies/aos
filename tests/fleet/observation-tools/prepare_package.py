"""Validate selected runtime artifacts and prepare the independent helper source."""

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

from extract import extract
from producer_inputs import PAIRS, commitments


def digest_file(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def prepare(spec_path, helper, output):
    spec = json.loads(Path(spec_path).read_bytes())
    runtime, helper, output = Path(spec['runtimeSource']), Path(helper), Path(output)
    provenance = spec['runtimeProvenance']
    if set(provenance) != {'version', 'runtimeCodecRevision', 'nativeExecutableSha256',
                          'workerSourceDigest', 'sourceArchiveSha256', 'browserSource'}:
        raise ValueError('Selected runtime provenance schema differs')
    if (provenance['version'] != 1 or provenance['runtimeCodecRevision'] != spec['sourceCommit']
            or provenance['workerSourceDigest'] != spec['workerSourceDigest']
            or digest_file(spec['nativeExecutable']) != provenance['nativeExecutableSha256']
            or digest_file(spec['runtimeArchive']) != provenance['sourceArchiveSha256']):
        raise ValueError('Selected source/artifact correspondence differs')
    # The source archive is an independent actual Git image. Verify all linked
    # production crate inputs and reused readers, without claiming runtime work.
    with tarfile.open(spec['runtimeArchive']) as archive:
        if archive.pax_headers.get('comment') != spec['sourceCommit']:
            raise ValueError('Actual Git archive commit differs')
        for item in archive:
            if not item.name.startswith(('crates/', 'tests/fleet/')) or not item.isfile():
                continue
            if item.size > 64 * 1024 * 1024 or '..' in Path(item.name).parts:
                raise ValueError('Source archive member exceeds bound')
            expected = runtime / item.name
            if not expected.is_file():
                raise ValueError('Selected runtime source member is absent')
            stream = archive.extractfile(item)
            if stream is None or hashlib.file_digest(stream, 'sha256').hexdigest() != digest_file(expected):
                raise ValueError('Selected runtime source differs from actual archive')
    client_path = spec['clientExecutable']
    client = None
    if client_path is not None:
        client = {'file': client_path, 'sha256': digest_file(client_path),
                  'byteSize': str(Path(client_path).stat().st_size)}
        if (runtime / PAIRS['client'][1]).exists():
            for relative in PAIRS['client']:
                if digest_file(Path(spec['clientSource']) / relative) != digest_file(runtime / relative):
                    raise ValueError('Client artifact producer source differs from selected archive')
    spec['clientExecutable'] = client
    spec['producerSha256'] = commitments(runtime, client)
    (output / 'tests/fleet').mkdir(parents=True)
    shutil.copytree(helper / 'tests/fleet/storage-body-codec', output / 'tests/fleet/storage-body-codec')
    shutil.copytree(helper / 'tests/fleet/observation-tools', output / 'tests/fleet/observation-tools')
    (output / 'crates').symlink_to(runtime / 'crates')
    # Store inputs are read-only; only these private prepared copies are edited.
    for path in (output / 'tests').rglob('*'):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)
    extract(runtime, output / 'tests/fleet/storage-body-codec/src/native',
            provenance, spec['nativeContract'])
    (output / 'selected-build-inputs.json').write_text(json.dumps(spec, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Expected selected spec, helper source and output')
    prepare(*sys.argv[1:])
