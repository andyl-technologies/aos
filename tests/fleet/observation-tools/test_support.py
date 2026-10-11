"""Create owned synthetic capture fixtures for installed helper tests."""

import json
from pathlib import Path
import shutil
import tempfile


OWNER = tempfile.TemporaryDirectory(prefix='aos-observation-packaged-tests-')
ROOT = Path(OWNER.name)


def fixtures(directory):
    target = ROOT / str(len(list(ROOT.iterdir())))
    target.mkdir(mode=0o700)
    proof = target / 'cli-proof'
    shutil.copytree(Path(directory) / 'fixtures', proof)
    for path in proof.iterdir():
        if path.is_file():
            path.chmod(0o600)
    manifest = json.loads((proof / 'positive-manifest.json').read_bytes())
    for capture in manifest['captures']:
        for reference in capture['bodies'].values():
            reference['file'] = str(proof / Path(reference['file']).name)
        for slot in ('controlSelection', 'storageWorkSelection'):
            if capture.get(slot):
                for value in capture[slot].values():
                    if isinstance(value, dict) and 'file' in value:
                        value['file'] = str(proof / Path(value['file']).name)
    (proof / 'positive-manifest.json').write_text(json.dumps(manifest, separators=(',', ':')))
    shutil.copyfile(proof / 'runtime-provenance.json', target / 'runtime-provenance.json')
    (target / 'runtime-provenance.json').chmod(0o600)
    return target
