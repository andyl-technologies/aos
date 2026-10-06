"""Install helper wrappers and a measured build record, separate from runtime."""

import hashlib
import json
from pathlib import Path
import shutil
import sys


def reference(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'file': str(path), 'sha256': digest, 'byteSize': str(path.stat().st_size)}


def install(prepared, tool_source, codec, output, python, bash):
    prepared, codec, output = Path(prepared), Path(codec), Path(output)
    spec = json.loads((prepared / 'selected-build-inputs.json').read_bytes())
    library = output / 'libexec/aos-observation-tools'
    library.mkdir(parents=True)
    source = Path(tool_source) / 'tests/fleet/observation-tools'
    for name in ('native_auth.py', 'hosted_assessment.py', 'package_context.py',
                 'native_auth_tests.py', 'hosted_assessment_tests.py', 'test_support.py',
                 'producer_inputs.py', 'render_private_wrapper.py', 'native_inventory.py',
                 'native_inventory_tests.py'):
        shutil.copyfile(source / name, library / name)
    shutil.copytree(source / 'fixtures', library / 'fixtures')
    provenance = spec['runtimeProvenance']
    context = {'version': 1, 'runtimeSource': spec['runtimeSource'],
               'runtimeProvenance': provenance,
               'runtime': {name: provenance[name] for name in ('runtimeCodecRevision',
                   'nativeExecutableSha256', 'workerSourceDigest', 'sourceArchiveSha256')},
               'sourceTree': spec['sourceTree'], 'nativeAuth': reference(library / 'native_auth.py'),
               'observerExecutable': reference(codec / 'bin/aos-storage-body-codec'),
               'captureImplementationSha256': None, 'producerSha256': spec['producerSha256'],
               'clientExecutable': spec['clientExecutable']}
    (library / 'package-context.json').write_text(json.dumps(context, indent=2) + '\n')
    binary = output / 'bin'
    binary.mkdir()
    commands = {'aos-native-body-observer': f'{codec}/bin/aos-storage-body-codec native-bodies',
                'aos-native-body-auth': f'{python} -B -E {library}/native_auth.py',
                'aos-hosted-byte-assessment': f'{python} -B -E {library}/hosted_assessment.py',
                'aos-observation-private-wrapper': f'{python} -B -E {library}/render_private_wrapper.py'}
    for name, command in commands.items():
        path = binary / name
        path.write_text(f'#!{bash}\nexec {command} "$@"\n')
        path.chmod(0o755)
    record = {'version': 1, 'claim': 'helper_build_only', 'runtimeInputs': spec,
              'preparedSource': str(prepared), 'pythonSource': str(tool_source), 'codecOutput': str(codec),
              'rustSourceFiles': [dict(reference(path), relativePath=str(path.relative_to(prepared)))
                  for path in sorted((prepared / 'tests/fleet/storage-body-codec/src').rglob('*')) if path.is_file()]
                  + [reference(prepared / 'tests/fleet/storage-body-codec' / name) for name in ('Cargo.toml', 'Cargo.lock')],
              'extraction': json.loads((prepared / 'tests/fleet/storage-body-codec/src/native/extraction.json').read_bytes()),
              'helperFiles': [reference(path) for path in sorted(library.glob('*.py'))],
              'context': reference(library / 'package-context.json'),
              'wrappers': [reference(path) for path in sorted(binary.iterdir())],
              'underlyingExecutable': context['observerExecutable']}
    (output / 'helper-build-provenance.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 7:
        raise SystemExit('Expected prepared source, Python source, codec, output, Python and Bash')
    install(*sys.argv[1:])
